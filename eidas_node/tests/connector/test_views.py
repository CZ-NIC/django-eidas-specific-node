from base64 import b64decode, b64encode
from datetime import datetime
from typing import BinaryIO, Dict, List, Tuple, cast
from unittest.mock import MagicMock, call, patch

from django.test import RequestFactory
from django.test.testcases import SimpleTestCase
from django.urls import reverse
from django.utils.datastructures import MultiValueDictKeyError
from freezegun import freeze_time

from eidas_node.attributes import EIDAS_NATURAL_PERSON_PREFIX
from eidas_node.connector.views import ConnectorResponseView, ServiceProviderRequestView
from eidas_node.errors import ParseError, SecurityError
from eidas_node.models import LightRequest, LightResponse, LightToken, Status
from eidas_node.saml import Q_NAMES, SAMLRequest
from eidas_node.storage.ignite import IgniteStorage
from eidas_node.tests.settings import DATA_DIR
from eidas_node.tests.test_models import LIGHT_REQUEST_DICT
from eidas_node.tests.test_saml import LIGHT_RESPONSE_DICT
from eidas_node.tests.test_storage import IgniteMockMixin
from eidas_node.utils import dump_xml, parse_xml


class TestCitizenCountrySelectorView(SimpleTestCase):
    SAML_REQUEST = b64encode(b'<SAMLRequest>...</SAMLRequest>').decode('ascii')

    def setUp(self):
        self.url = reverse('country-selector')
        self.request_endpoint = reverse('service-provider-request')

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertNotContains(response, self.request_endpoint, status_code=405)

    def test_post_without_saml_request(self):
        response = self.client.post(self.url)

        # Context
        self.assertEqual(response.context['error'], 'Bad service provider request.')
        self.assertEqual(response.context['saml_request'], None)
        self.assertEqual(response.context['relay_state'], '')
        self.assertEqual(response.context['request_endpoint'], self.request_endpoint)
        self.assertEqual(response.context['citizen_country'], None)
        self.assertEqual(response.context['country_parameter'], 'country_param')
        self.assertEqual(response.context['countries'], [('CA', 'Test Country'), ('CZ', 'Another Country')])

        # Rendering
        self.assertNotIn(self.request_endpoint.encode('utf-8'), response.content)
        self.assertContains(response,
                            'An error occurred during processing of Service Provider request.',
                            status_code=400)

    def test_post_without_country(self):
        response = self.client.post(self.url, {'SAMLRequest': self.SAML_REQUEST, 'RelayState': 'xyz'})

        # Context
        self.assertEqual(response.context['error'], None)
        self.assertEqual(response.context['saml_request'], self.SAML_REQUEST)
        self.assertEqual(response.context['relay_state'], 'xyz')
        self.assertEqual(response.context['request_endpoint'], self.request_endpoint)
        self.assertEqual(response.context['citizen_country'], None)
        self.assertEqual(response.context['country_parameter'], 'country_param')
        self.assertEqual(response.context['countries'], [('CA', 'Test Country'), ('CZ', 'Another Country')])

        # Rendering
        self.assertContains(response, self.request_endpoint)
        self.assertContains(response, 'Choose your country to proceed with authentication')
        self.assertContains(response, '<form id="country-selector-form" action="{}"'.format(self.request_endpoint))
        self.assertContains(response, '<button type="submit" name="country_param" value="CA" title="CA">')
        self.assertContains(response, '<span class="flag flag-ca"></span>Test Country')
        self.assertContains(response, '<button type="submit" name="country_param" value="CZ" title="CZ">')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'.format(self.SAML_REQUEST))
        self.assertContains(response, '<input type="hidden" name="RelayState" value="xyz"/>')
        self.assertNotContains(response, 'An error occurred')

    def test_post_with_country(self):
        response = self.client.post(self.url, {
            'SAMLRequest': self.SAML_REQUEST, 'RelayState': 'xyz', 'country_param': 'CC'})

        # Context
        self.assertEqual(response.context['error'], None)
        self.assertEqual(response.context['saml_request'], self.SAML_REQUEST)
        self.assertEqual(response.context['relay_state'], 'xyz')
        self.assertEqual(response.context['request_endpoint'], self.request_endpoint)
        self.assertEqual(response.context['citizen_country'], 'CC')
        self.assertEqual(response.context['country_parameter'], 'country_param')
        self.assertEqual(response.context['countries'], [('CA', 'Test Country'), ('CZ', 'Another Country')])

        # Rendering
        self.assertContains(response, self.request_endpoint)
        self.assertContains(response, 'Redirect to Identity Provider is in progress')
        self.assertContains(response, 'eidas_node/connector/formautosubmit.js')
        self.assertContains(response, '<form class="auto-submit" action="{}"'.format(self.request_endpoint))
        self.assertContains(response, '<input type="hidden" name="country_param" value="CC"/>')
        self.assertContains(response, '<input type="submit" value="Continue"/>')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'.format(self.SAML_REQUEST))
        self.assertContains(response, '<input type="hidden" name="RelayState" value="xyz"/>')
        self.assertNotContains(response, 'An error occurred')


class TestServiceProviderRequestView(IgniteMockMixin, SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse('service-provider-request')
        self.addCleanup(self.mock_ignite_cache())

    def load_saml_request(self) -> Tuple[str, str]:
        with cast(BinaryIO, (DATA_DIR / 'saml_request.xml').open('rb')) as f:
            saml_request_xml = f.read()
        return saml_request_xml.decode('utf-8'), b64encode(saml_request_xml).decode('ascii')

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEquals(response.status_code, 405)
        self.assertNotIn(b'http://test.example.net/SpecificConnectorRequest', response.content)

    def test_get_saml_request_without_saml_request(self):
        view = ServiceProviderRequestView()
        view.request = self.factory.post(self.url, {'country_param': 'ca'})
        with self.assertRaisesMessage(ParseError, 'Document is empty'):
            view.get_saml_request('country_param')

    def test_get_saml_request_without_country(self):
        saml_request_xml, saml_request_encoded = self.load_saml_request()
        view = ServiceProviderRequestView()
        view.request = self.factory.post(self.url, {'SAMLRequest': saml_request_encoded})
        with self.assertRaisesMessage(MultiValueDictKeyError, 'country_param'):
            view.get_saml_request('country_param')

    def test_get_saml_request_without_relay_state(self):
        saml_request_xml, saml_request_encoded = self.load_saml_request()
        view = ServiceProviderRequestView()
        view.request = self.factory.post(self.url, {'SAMLRequest': saml_request_encoded, 'country_param': 'ca'})
        saml_request = view.get_saml_request('country_param')
        self.assertXMLEqual(dump_xml(saml_request.document).decode('utf-8'), saml_request_xml)
        self.assertEqual(saml_request.citizen_country_code, 'CA')
        self.assertEqual(saml_request.relay_state, None)

    def test_get_saml_request_with_relay_state(self):
        saml_request_xml, saml_request_encoded = self.load_saml_request()
        view = ServiceProviderRequestView()
        view.request = self.factory.post(self.url, {
            'SAMLRequest': saml_request_encoded,
            'RelayState': 'xyz',
            'country_param': 'ca',
        })
        saml_request = view.get_saml_request('country_param')
        self.assertXMLEqual(dump_xml(saml_request.document).decode('utf-8'), saml_request_xml)
        self.assertEqual(saml_request.citizen_country_code, 'CA')
        self.assertEqual(saml_request.relay_state, 'xyz')

    def test_create_light_request_wrong_issuer(self):
        saml_request_xml, _saml_request_encoded = self.load_saml_request()
        view = ServiceProviderRequestView()
        view.saml_request = SAMLRequest(parse_xml(saml_request_xml), 'ca', 'xyz')
        with self.assertRaisesMessage(SecurityError, 'Invalid SAML request issuer'):
            view.create_light_request('wrong-saml-issuer', 'test-light-request-issuer')

    def test_create_light_request_our_issuer_set(self):
        saml_request_xml, _saml_request_encoded = self.load_saml_request()
        view = ServiceProviderRequestView()
        view.saml_request = SAMLRequest(parse_xml(saml_request_xml), 'ca', 'xyz')
        light_request = view.create_light_request('test-saml-request-issuer', 'test-light-request-issuer')
        self.assertEqual(light_request.issuer, 'test-light-request-issuer')

    def test_adjust_requested_attributes(self):
        view = ServiceProviderRequestView()
        attributes = {}  # type: Dict[str, List[str]]
        view.adjust_requested_attributes(attributes)
        self.assertEqual(attributes, {
            EIDAS_NATURAL_PERSON_PREFIX + i: []
            for i in ('PersonIdentifier', 'CurrentFamilyName', 'CurrentGivenName', 'DateOfBirth')})

    @freeze_time('2017-12-11 14:12:05')
    @patch('eidas_node.utils.uuid4', return_value='0uuid4')
    def test_create_light_token(self, uuid_mock: MagicMock):
        view = ServiceProviderRequestView()
        light_request_data = LIGHT_REQUEST_DICT.copy()
        view.light_request = LightRequest(**light_request_data)

        token, encoded_token = view.create_light_token('test-token-issuer', 'sha256', 'test-secret')
        self.assertEqual(token.id, 'T0uuid4')
        self.assertEqual(token.issuer, 'test-token-issuer')
        self.assertEqual(token.created, datetime(2017, 12, 11, 14, 12, 5))
        self.assertEqual(token.encode('sha256', 'test-secret').decode('ascii'), encoded_token)
        self.assertEqual(uuid_mock.mock_calls, [call()])

    @freeze_time('2017-12-11 14:12:05')
    @patch('eidas_node.utils.uuid4', return_value='0uuid4')
    def test_post_success(self, uuid_mock: MagicMock):
        self.maxDiff = None
        saml_request_xml, saml_request_encoded = self.load_saml_request()
        light_request = LightRequest(**LIGHT_REQUEST_DICT)
        light_request.issuer = 'https://example.net/EidasNode/ConnectorMetadata'
        self.cache_mock.get.return_value = dump_xml(light_request.export_xml()).decode('utf-8')

        response = self.client.post(self.url, {'SAMLRequest': saml_request_encoded,
                                               'RelayState': 'relay123',
                                               'country_param': 'ca'})

        # Context
        self.assertIn('token', response.context)
        self.assertEqual(response.context['token_parameter'], 'test_request_token')
        self.assertEqual(response.context['eidas_url'], 'http://test.example.net/SpecificConnectorRequest')
        self.assertEqual(response.context['error'], None)

        # Token
        encoded_token = response.context['token']
        token = LightToken.decode(encoded_token, 'sha256', 'request-token-secret')
        self.assertEqual(token.id, 'T0uuid4')
        self.assertEqual(token.issuer, 'request-token-issuer')
        self.assertEqual(token.created, datetime(2017, 12, 11, 14, 12, 5))

        # Storing light request
        light_request_data = LIGHT_REQUEST_DICT.copy()
        light_request_data.update({
            'id': 'test-saml-request-id',
            'issuer': 'test-connector-request-issuer',
        })
        light_request = LightRequest(**light_request_data)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=66)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect('test.example.net', 1234),
                          call.get_cache('test-connector-request-cache'),
                          call.get_cache().put('T0uuid4', dump_xml(light_request.export_xml()).decode('utf-8'))])

        # Rendering
        self.assertContains(response, 'Redirect to Identity Provider is in progress')
        self.assertContains(response, 'eidas_node/connector/formautosubmit.js')
        self.assertContains(response, '<form class="auto-submit" '
                                      'action="http://test.example.net/SpecificConnectorRequest"')
        self.assertContains(response, '<input type="hidden" name="test_request_token" value="{}"'.format(encoded_token))
        self.assertNotIn(b'An error occurred', response.content)

    def test_post_failure(self):
        response = self.client.post(self.url)
        self.assertNotIn(b'http://test.example.net/SpecificConnectorRequest', response.content)
        self.assertContains(response,
                            'An error occurred during processing of Service Provider request.',
                            status_code=400)
        self.assertContains(response, 'An error occurred', status_code=400)
        self.assertEqual(response.context['error'], 'Bad service provider request.')
        self.assertNotIn('eidas_url', response.context)
        self.assertNotIn('token', response.context)
        self.assertNotIn('token_parameter', response.context)


class TestConnectorResponseView(IgniteMockMixin, SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse('connector-response')
        self.addCleanup(self.mock_ignite_cache())

    def get_token(self, issuer: str = None) -> Tuple[LightToken, str]:
        token = LightToken(id='response-token-id',
                           issuer=issuer or 'response-token-issuer',
                           created=datetime(2017, 12, 11, 14, 12, 5, 148000))
        encoded = token.encode('sha256', 'response-token-secret').decode('utf-8')
        return token, encoded

    def get_light_response(self, **kwargs) -> LightResponse:
        light_response_data = LIGHT_RESPONSE_DICT.copy()
        light_response_data['status'] = Status(**light_response_data['status'])
        light_response_data.update(**kwargs)
        return LightResponse(**light_response_data)

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEquals(response.status_code, 405)
        self.assertNotIn(b'/DemoServiceProviderResponse', response.content)

    def test_get_light_token_no_token(self):
        view = ConnectorResponseView()
        view.request = self.factory.post(self.url)
        with self.assertRaisesMessage(ParseError, 'Token has wrong number of parts'):
            view.get_light_token('test_token', 'response-token-issuer', 'sha256', 'response-token-secret')

    def test_get_light_token_expired(self):
        _token, encoded = self.get_token()
        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        with self.assertRaisesMessage(SecurityError, 'Token has expired'):
            view.get_light_token('test_token', 'response-token-issuer', 'sha256', 'response-token-secret', 1)

    def test_get_light_token_success(self):
        orig_token, encoded = self.get_token()
        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        token = view.get_light_token('test_token', 'response-token-issuer', 'sha256', 'response-token-secret', 0)
        self.assertEqual(token, orig_token)

    @freeze_time('2017-12-11 14:12:05')
    def test_get_light_token_wrong_issuer(self):
        _token, encoded = self.get_token('wrong-issuer')
        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})

        with self.assertRaisesMessage(SecurityError, 'Invalid token issuer'):
            view.get_light_token('test_token', 'response-token-issuer', 'sha256', 'response-token-secret')

    def test_get_light_response_not_found(self):
        self.cache_mock.get.return_value = None
        token, encoded = self.get_token()

        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.storage = IgniteStorage('test.example.net', 1234, 'test-connector-response-cache', '')

        with self.assertRaisesMessage(SecurityError, 'Response not found in light storage'):
            view.get_light_response()

    def test_get_light_response_success(self):
        orig_light_response = self.get_light_response()
        self.cache_mock.get.return_value = dump_xml(orig_light_response.export_xml()).decode('utf-8')
        token, encoded = self.get_token()

        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.storage = IgniteStorage('test.example.net', 1234, '', 'test-connector-response-cache')

        light_response = view.get_light_response()
        self.assertEqual(light_response, orig_light_response)
        self.maxDiff = None
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect('test.example.net', 1234),
                          call.get_cache('test-connector-response-cache'),
                          call.get_cache().get('response-token-id')])

    @freeze_time('2017-12-11 14:12:05')
    def test_create_saml_response(self):
        light_response = self.get_light_response()
        token, encoded = self.get_token()

        view = ConnectorResponseView()
        view.request = self.factory.post(self.url, {'test_token': encoded})
        view.light_token = token
        view.light_response = light_response

        saml_response = view.create_saml_response(
            'light-request-issuer',
            'https://test.example.net/DemoServiceProviderResponse')
        root = saml_response.document.getroot()
        self.assertEqual(root.get('ID'), light_response.id)
        self.assertEqual(root.get('IssueInstant'), '2017-12-11T14:12:05.000Z')
        self.assertEqual(root.find(".//{}".format(Q_NAMES['saml2:Issuer'])).text,
                         'light-request-issuer')

    @freeze_time('2017-12-11 14:12:05')
    def test_post_success(self):
        self.maxDiff = None
        light_response = self.get_light_response()
        self.cache_mock.get.return_value = dump_xml(light_response.export_xml()).decode('utf-8')

        token, encoded = self.get_token()
        response = self.client.post(self.url, {'test_response_token': encoded})

        # Context
        self.assertEqual(response.context['error'], None)
        self.assertIn('saml_response', response.context)
        self.assertEqual(response.context['service_provider_endpoint'], '/DemoServiceProviderResponse')
        self.assertEqual(response.context['relay_state'], 'relay123')

        # SAML Response
        saml_response_xml = b64decode(response.context['saml_response'].encode('utf-8')).decode('utf-8')
        self.assertIn(light_response.id, saml_response_xml)  # light_response.id preserved
        self.assertIn('<saml2:Issuer>test-saml-response-issuer</saml2:Issuer>', saml_response_xml)
        self.assertIn('Destination="/DemoServiceProviderResponse"', saml_response_xml)

        # Rendering
        self.assertContains(response, 'Redirect to Service Provider is in progress')
        self.assertContains(response, 'eidas_node/connector/formautosubmit.js')
        self.assertContains(response, '<form class="auto-submit" action="/DemoServiceProviderResponse"')
        self.assertContains(response, '<input type="hidden" name="SAMLResponse" value="{}"'.format(
            response.context['saml_response']))
        self.assertContains(response, '<input type="hidden" name="RelayState" value="relay123"/>')
        self.assertNotIn(b'An error occurred', response.content)

    def test_post_failure(self):
        response = self.client.post(self.url)
        self.assertNotIn(b'/DemoServiceProviderResponse', response.content)
        self.assertContains(response,
                            'An error occurred during processing of Identity Provider response.',
                            status_code=400)
        self.assertEqual(response.context['error'], 'Bad connector response.')
        self.assertNotIn('identity_provider_endpoint', response.context)
        self.assertNotIn('saml_response', response.context)
        self.assertNotIn('relay_state', response.context)
