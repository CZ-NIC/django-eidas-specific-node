from base64 import b64decode, b64encode
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Optional, TextIO, Tuple, cast
from unittest.mock import MagicMock, PropertyMock, call, patch, sentinel

from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse
from freezegun import freeze_time
from lxml.etree import Element, SubElement

from eidas_node.constants import NameIdFormat
from eidas_node.errors import ParseError, SecurityError
from eidas_node.models import LightRequest, LightResponse, LightToken, Status
from eidas_node.proxy_service.views import IdentityProviderResponseView, ProxyServiceRequestView
from eidas_node.saml import EIDAS_NAMESPACES, Q_NAMES, SAMLResponse
from eidas_node.storage.ignite import IgniteStorage
from eidas_node.tests.constants import (AUXILIARY_STORAGE, CERT_FILE, KEY_FILE, NIA_CERT_FILE, SIGNATURE_OPTIONS,
                                        WRONG_CERT_FILE)
from eidas_node.tests.test_models import FAILED_LIGHT_RESPONSE_DICT, LIGHT_REQUEST_DICT, LIGHT_RESPONSE_DICT
from eidas_node.tests.test_storage import IgniteMockMixin
from eidas_node.xml import dump_xml, parse_xml, remove_extra_xml_whitespace

DATA_DIR: Path = Path(__file__).parent.parent / 'data'


class TestProxyServiceRequestView(IgniteMockMixin, SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse('proxy-service-request')
        self.addCleanup(self.mock_ignite_cache())

    def get_token(self, issuer: Optional[str] = None) -> Tuple[LightToken, str]:
        token = LightToken(id='request-token-id',
                           issuer=issuer or 'request-token-issuer',
                           created=datetime(2017, 12, 11, 14, 12, 5, 148000))
        encoded = token.encode('sha256', 'request-token-secret').decode('utf-8')
        return token, encoded

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        self.assertNotIn(b'https://example.net/identity-provider-endpoint', response.content)

    def test_get_light_token_no_token(self):
        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url)
        with self.assertRaisesMessage(ParseError, 'Token has wrong number of parts'):
            view.get_light_token('test_token', 'request-token-issuer', 'sha256', 'request-token-secret')

    def test_get_light_token_expired(self):
        _token, encoded = self.get_token()
        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        with self.assertRaisesMessage(SecurityError, 'Token has expired'):
            view.get_light_token('test_token', 'request-token-issuer', 'sha256', 'request-token-secret', 1)

    def test_get_light_token_success(self):
        orig_token, encoded = self.get_token()
        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        token = view.get_light_token('test_token', 'request-token-issuer', 'sha256', 'request-token-secret', 0)
        self.assertEqual(token, orig_token)

    @freeze_time('2017-12-11 14:12:05')
    def test_get_light_token_wrong_issuer(self):
        _token, encoded = self.get_token('wrong-issuer')
        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})

        with self.assertRaisesMessage(SecurityError, 'Invalid token issuer'):
            view.get_light_token('test_token', 'request-token-issuer', 'sha256', 'request-token-secret')

    def test_get_light_request_not_found(self):
        self.cache_mock.get_and_remove.return_value = None
        token, encoded = self.get_token()

        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.storage = IgniteStorage('test.example.net', 1234, 'test-proxy-service-request-cache', '')

        with self.assertRaisesMessage(SecurityError, 'Request not found in light storage'):
            view.get_light_request()

    def test_get_light_request_success(self):
        orig_light_request = LightRequest(**LIGHT_REQUEST_DICT)
        self.cache_mock.get_and_remove.return_value = dump_xml(orig_light_request.export_xml()).decode('utf-8')
        token, encoded = self.get_token()

        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.storage = IgniteStorage('test.example.net', 1234, 'test-proxy-service-request-cache', '')

        light_request = view.get_light_request()
        self.assertEqual(light_request, orig_light_request)
        self.maxDiff = None
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect('test.example.net', 1234),
                          call.get_cache('test-proxy-service-request-cache'),
                          call.get_cache().get_and_remove('request-token-id')])

    @freeze_time('2017-12-11 14:12:05')
    def test_create_saml_request(self):
        light_request = LightRequest(**LIGHT_REQUEST_DICT)
        token, encoded = self.get_token()

        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.light_request = light_request

        saml_request = view.create_saml_request('https://test.example.net/saml/idp.xml', None)
        root = saml_request.document.getroot()
        self.assertEqual(root.get('ID'), 'test-light-request-id')
        self.assertEqual(root.get('IssueInstant'), '2017-12-11T14:12:05.000Z')
        self.assertEqual(root.find(".//{}".format(Q_NAMES['saml2:Issuer'])).text,
                         'https://test.example.net/saml/idp.xml')
        self.assertIsNone(root.find('./{}'.format(Q_NAMES['ds:Signature'])))

    @freeze_time('2017-12-11 14:12:05')
    def test_create_saml_request_signed(self):
        light_request = LightRequest(**LIGHT_REQUEST_DICT)
        token, encoded = self.get_token()

        view = ProxyServiceRequestView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.light_request = light_request

        saml_request = view.create_saml_request('https://test.example.net/saml/idp.xml', SIGNATURE_OPTIONS)
        root = saml_request.document.getroot()
        self.assertEqual(root.get('ID'), 'test-light-request-id')
        self.assertEqual(root.get('IssueInstant'), '2017-12-11T14:12:05.000Z')
        self.assertEqual(root.find(".//{}".format(Q_NAMES['saml2:Issuer'])).text,
                         'https://test.example.net/saml/idp.xml')
        self.assertIsNotNone(root.find('./{}'.format(Q_NAMES['ds:Signature'])))

    @freeze_time('2017-12-11 14:12:05')
    def test_post_success(self):
        self.maxDiff = None
        request = LightRequest(**LIGHT_REQUEST_DICT)
        self.cache_mock.get_and_remove.return_value = dump_xml(request.export_xml()).decode('utf-8')

        token, encoded = self.get_token()
        response = self.client.post(self.url, {'test_token': encoded})

        # Context
        self.assertIn('saml_request', response.context)
        self.assertEqual(response.context['identity_provider_endpoint'],
                         'https://test.example.net/identity-provider-endpoint')
        self.assertEqual(response.context['relay_state'], 'relay123')
        self.assertEqual(response.context['error'], None)

        # SAML Request
        saml_request_xml = b64decode(response.context['saml_request'].encode('utf-8')).decode('utf-8')
        self.assertIn(request.id, saml_request_xml)  # light_request.id preserved
        self.assertIn('<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
                      'https://test.example.net/saml/idp.xml</saml2:Issuer>', saml_request_xml)
        self.assertIn('Destination="http://testserver/IdentityProviderResponse"', saml_request_xml)
        self.assertIn('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>', saml_request_xml)

        # Rendering
        self.assertContains(response, 'Redirect to Identity Provider is in progress')
        self.assertContains(response,
                            '<form class="auto-submit" action="https://test.example.net/identity-provider-endpoint"')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"'.format(
            response.context['saml_request']))
        self.assertContains(response, '<input type="hidden" name="RelayState" value="relay123"/>')
        self.assertNotIn(b'An error occurred', response.content)

    def test_post_failure(self):
        response = self.client.post(self.url)
        self.assertNotIn(b'https://example.net/identity-provider-endpoint', response.content)
        self.assertContains(response,
                            'An error occurred during processing of eIDAS Node request.',
                            status_code=400)
        self.assertEqual(response.context['error'], 'Bad proxy service request.')
        self.assertNotIn('identity_provider_endpoint', response.context)
        self.assertNotIn('saml_request', response.context)
        self.assertNotIn('relay_state', response.context)

    @freeze_time('2017-12-11 14:12:05')
    @override_settings(PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True,
                       PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE)
    def test_post_remember_name_id_format(self):
        request = LightRequest(**LIGHT_REQUEST_DICT)
        self.cache_mock.get_and_remove.return_value = dump_xml(request.export_xml()).decode('utf-8')

        token, encoded = self.get_token()
        response = self.client.post(self.url, {'test_token': encoded})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.client_mock.mock_calls,
            [
                call.connect('test.example.net', 1234),
                call.get_cache('test-proxy-service-request-cache'),
                call.get_cache().get_and_remove('request-token-id'),
                call.connect('test.example.net', 1234),
                call.get_cache('aux-cache'),
                call.get_cache().put(
                    'aux-test-light-request-id',
                    '{"name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}'
                ),
            ]
        )

    @freeze_time('2017-12-11 14:12:05')
    @override_settings(PROXY_SERVICE_TRACK_COUNTRY_CODE=True,
                       PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE)
    def test_post_remember_country_codes(self):
        request = LightRequest(**LIGHT_REQUEST_DICT)
        self.cache_mock.get_and_remove.return_value = dump_xml(request.export_xml()).decode('utf-8')

        token, encoded = self.get_token()
        response = self.client.post(self.url, {'test_token': encoded})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.client_mock.mock_calls,
            [
                call.connect('test.example.net', 1234),
                call.get_cache('test-proxy-service-request-cache'),
                call.get_cache().get_and_remove('request-token-id'),
                call.connect('test.example.net', 1234),
                call.get_cache('aux-cache'),
                call.get_cache().put(
                    'aux-test-light-request-id',
                    '{"citizen_country": "CA", "origin_country": "CA"}'
                ),
            ]
        )


class TestIdentityProviderResponseView(IgniteMockMixin, SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse('identity-provider-response')
        self.addCleanup(self.mock_ignite_cache())

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        self.assertNotIn(b'https://example.net/EidasNode/SpecificProxyServiceResponse', response.content)

    def test_get_saml_response_no_data(self):
        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url)
        self.assertRaises(ParseError, view.get_saml_response, None, None)

    def test_get_saml_response_relay_state_optional(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            saml_response_xml = f.read()

        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url, {'SAMLResponse': b64encode(saml_response_xml).decode('ascii')})
        saml_response = view.get_saml_response(None, None)
        self.assertIsNone(saml_response.relay_state)

    def test_get_saml_response_encrypted(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response_encrypted.xml').open('rb')) as f:
            saml_response_xml = f.read()

        with cast(TextIO, (DATA_DIR / 'saml_response_decrypted.xml').open('r')) as f2:
            decrypted_saml_response_xml = f2.read()

        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url, {'SAMLResponse': b64encode(saml_response_xml).decode('ascii'),
                                                    'RelayState': 'relay123'})
        saml_response = view.get_saml_response(KEY_FILE, None)
        self.assertEqual(saml_response.relay_state, 'relay123')
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), decrypted_saml_response_xml)

    def test_get_saml_response_signed(self):
        with cast(TextIO, (DATA_DIR / 'signed_response_and_assertion.xml').open('r')) as f:
            tree = parse_xml(f.read())
        remove_extra_xml_whitespace(tree)
        saml_response_encoded = b64encode(dump_xml(tree, pretty_print=False)).decode('ascii')

        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url, {'SAMLResponse': saml_response_encoded, 'RelayState': 'relay123'})
        saml_response = view.get_saml_response(None, CERT_FILE)
        self.assertEqual(saml_response.relay_state, 'relay123')

        root = Element(Q_NAMES['saml2p:Response'], {'ID': 'id-response'},
                       nsmap={'saml2': EIDAS_NAMESPACES['saml2'], 'saml2p': EIDAS_NAMESPACES['saml2p']})
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'], {'ID': 'id-0uuid4'})
        SubElement(assertion, Q_NAMES['saml2:Issuer']).text = 'Test Issuer'
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), dump_xml(root).decode('utf-8'))

    def test_get_saml_response_invalid_signature(self):
        with cast(TextIO, (DATA_DIR / 'signed_response_and_assertion.xml').open('r')) as f:
            tree = parse_xml(f.read())
        remove_extra_xml_whitespace(tree)
        saml_response_encoded = b64encode(dump_xml(tree, pretty_print=False)).decode('ascii')

        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url, {'SAMLResponse': saml_response_encoded})
        self.assertRaises(SecurityError, view.get_saml_response, None, WRONG_CERT_FILE)

    def test_get_saml_response_signed_and_encrypted(self):
        with cast(TextIO, (DATA_DIR / 'nia_test_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
        remove_extra_xml_whitespace(tree)
        saml_response_encoded = b64encode(dump_xml(tree, pretty_print=False)).decode('ascii')
        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url, {'SAMLResponse': saml_response_encoded, 'RelayState': 'relay123'})
        saml_response = view.get_saml_response(KEY_FILE, NIA_CERT_FILE)
        self.assertEqual(saml_response.relay_state, 'relay123')

        with cast(TextIO, (DATA_DIR / 'nia_test_response_decrypted_verified.xml').open('r')) as f:
            decrypted_verified_xml = f.read()
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), decrypted_verified_xml)

    def test_create_light_response_correct_id_and_issuer(self):
        self.maxDiff = None
        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url)

        with cast(TextIO, (DATA_DIR / 'saml_response.xml').open('r')) as f:
            view.saml_response = SAMLResponse(parse_xml(f.read()), 'relay123')

        light_response = view.create_light_response('test-light-response-issuer')
        self.assertEqual(light_response.id, 'test-saml-response-id')  # Preserved
        self.assertEqual(light_response.in_response_to_id, 'test-saml-request-id')  # Preserved
        self.assertEqual(light_response.issuer, 'test-light-response-issuer')  # Replaced

    def test_create_light_response_auth_class_alias(self):
        view = IdentityProviderResponseView()

        with patch.object(IdentityProviderResponseView, 'saml_response', new_callable=PropertyMock) as response_mock:
            view.create_light_response('test-light-response-issuer', sentinel.auth_class_map)

        self.assertSequenceEqual(response_mock.mock_calls,
                                 [call(), call().create_light_response(sentinel.auth_class_map)])

    @freeze_time('2017-12-11 14:12:05', tz_offset=2)
    @patch('eidas_node.xml.uuid4', return_value='0uuid4')
    def test_create_light_token(self, uuid_mock: MagicMock):
        view = IdentityProviderResponseView()
        view.request = self.factory.post(self.url)
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        view.light_response = LightResponse(**light_response_data)

        token, encoded_token = view.create_light_token('test-token-issuer', 'sha256', 'test-secret')
        self.assertEqual(token.id, 'T0uuid4')
        self.assertEqual(token.issuer, 'test-token-issuer')
        self.assertEqual(token.created, datetime(2017, 12, 11, 16, 12, 5))
        self.assertEqual(token.encode('sha256', 'test-secret').decode('ascii'), encoded_token)
        self.assertEqual(uuid_mock.mock_calls, [call()])

    @override_settings(PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=False)
    def test_rewrite_name_id_disabled(self):
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.PERSISTENT
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.PERSISTENT)
        self.assertEqual(view.light_response.subject, 'CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9')

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE,
                       PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True)
    def test_rewrite_name_id_failure(self):
        light_response_data = FAILED_LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.PERSISTENT
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {'name_id_format': NameIdFormat.TRANSIENT.value}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.PERSISTENT)
        self.assertIsNone(view.light_response.subject)

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE,
                       PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True)
    def test_rewrite_name_id_none(self):
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.PERSISTENT
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.PERSISTENT)
        self.assertEqual(view.light_response.subject, 'CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9')

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE,
                       PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True)
    @patch('eidas_node.proxy_service.views.uuid4', return_value='0uuid4')
    def test_rewrite_name_id_persistent_to_transient(self, uuid_mock):
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.PERSISTENT
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {'name_id_format': NameIdFormat.TRANSIENT.value}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.TRANSIENT)
        self.assertEqual(view.light_response.subject, '0uuid4')

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE,
                       PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True)
    @patch('eidas_node.proxy_service.views.uuid4', return_value='0uuid4')
    def test_rewrite_name_id_unspecified_to_transient(self, uuid_mock):
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.UNSPECIFIED
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {'name_id_format': NameIdFormat.TRANSIENT.value}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.TRANSIENT)
        self.assertEqual(view.light_response.subject, '0uuid4')

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE,
                       PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK=True)
    def test_rewrite_name_id_persistent(self):
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data['subject_name_id_format'] = NameIdFormat.PERSISTENT
        view = IdentityProviderResponseView()
        view.light_response = LightResponse(**light_response_data)
        view.auxiliary_data = {'name_id_format': NameIdFormat.PERSISTENT.value}

        view.rewrite_name_id()
        self.assertEqual(view.light_response.subject_name_id_format, NameIdFormat.PERSISTENT)
        self.assertEqual(view.light_response.subject, 'CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9')

    @freeze_time('2017-12-11 14:12:05')
    @patch('eidas_node.xml.uuid4', return_value='0uuid4')
    def test_post_success(self, uuid_mock: MagicMock):
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            saml_request_xml = f.read()

        response = self.client.post(self.url, {'SAMLResponse': b64encode(saml_request_xml).decode('ascii'),
                                               'RelayState': 'relay123'})

        # Context
        self.assertIn('token', response.context)
        self.assertEqual(response.context['token_parameter'], 'test_token')
        self.assertEqual(response.context['eidas_url'], 'https://test.example.net/SpecificProxyServiceResponse')
        self.assertEqual(response.context['error'], None)

        # Token
        encoded_token = response.context['token']
        token = LightToken.decode(encoded_token, 'sha256', 'response-token-secret')
        self.assertEqual(token.id, 'T0uuid4')
        self.assertEqual(token.issuer, 'response-token-issuer')
        self.assertEqual(token.created, datetime(2017, 12, 11, 14, 12, 5))

        # Storing light response
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data.update({
            'status': Status(**light_response_data['status']),
            'id': 'test-saml-response-id',  # Preserved
            'in_response_to_id': 'test-saml-request-id',  # Preserved
            'issuer': 'https://test.example.net/node-proxy-service-response',  # Replaced
        })
        light_response = LightResponse(**light_response_data)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=66)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect('test.example.net', 1234),
                          call.get_cache('test-proxy-service-response-cache'),
                          call.get_cache().put('T0uuid4', dump_xml(light_response.export_xml()).decode('utf-8'))])

        # Rendering
        self.assertContains(response, 'Redirect to eIDAS Node is in progress')
        self.assertContains(response,
                            '<form class="auto-submit" action="https://test.example.net/SpecificProxyServiceResponse"')
        self.assertContains(response, '<input type="hidden" name="test_token" value="{}"'.format(encoded_token))
        self.assertNotIn(b'An error occurred', response.content)

    def test_post_failure(self):
        response = self.client.post(self.url)
        self.assertNotIn(b'https://test.example.net/SpecificProxyServiceResponse', response.content)
        self.assertContains(response,
                            'An error occurred during processing of Identity Provider response.',
                            status_code=400)
        self.assertContains(response, 'An error occurred', status_code=400)
        self.assertEqual(response.context['error'], 'Bad identity provider response.')
        self.assertNotIn('eidas_url', response.context)
        self.assertNotIn('token', response.context)
        self.assertNotIn('token_parameter', response.context)

    @override_settings(PROXY_SERVICE_AUXILIARY_STORAGE=AUXILIARY_STORAGE)
    def test_post_load_auxiliary_data(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            saml_request_xml = f.read()
        self.cache_mock.get_and_remove.return_value = "{}"
        response = self.client.post(self.url, {'SAMLResponse': b64encode(saml_request_xml).decode('ascii'),
                                               'RelayState': 'relay123'})
        self.assertEqual(response.status_code, 200)
        self.maxDiff = None
        self.assertSequenceEqual(self.client_mock.mock_calls[:4], [
            call.connect('test.example.net', 1234),
            call.get_cache('aux-cache'),
            call.get_cache().get_and_remove('aux-test-saml-request-id'),
            call.connect('test.example.net', 1234)])
