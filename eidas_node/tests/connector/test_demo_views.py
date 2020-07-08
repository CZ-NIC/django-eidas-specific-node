from base64 import b64encode
from typing import Any, Dict, TextIO, cast

from django.test import override_settings
from django.test.testcases import SimpleTestCase
from django.urls import reverse

from eidas_node.tests.constants import DATA_DIR
from eidas_node.xml import dump_xml, parse_xml, remove_extra_xml_whitespace

CONNECTOR_SERVICE_PROVIDER_WITHOUT_SIGNATURE = {
    'ENDPOINT': '/DemoServiceProviderResponse',
    'REQUEST_ISSUER': 'test-saml-request-issuer',
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'COUNTRY_PARAMETER': 'country_param',
    'RESPONSE_SIGNATURE': {},
    'RESPONSE_ENCRYPTION': {},
}  # type: Dict[str, Any]


class TestDemoServiceProviderRequestView(SimpleTestCase):
    def setUp(self):
        self.url = reverse('demo-sp-request')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertContains(response, '<input type="text" name="RelayState" value=""/>')
        self.assertContains(response, '<input type="text" name="Country" value=""/>')
        self.assertContains(response,
                            '<button type="submit" name="Request" value="0">Request mandatory attributes,'
                            ' persistent name id</button>')
        self.assertContains(response,
                            '<button type="submit" name="Request" value="2">Request mandatory attributes,'
                            ' unspecified name id</button>')

    def test_post_wrong_preset(self):
        for params in {}, {'999': 'whatever'}, {'one': 'whatever'}:
            response = self.client.post(self.url, params)
            self.assertEqual(response.status_code, 400)

    def test_post_without_optional_params(self):
        response = self.client.post(self.url, {'Request': '1'})
        self.assertEqual(response.context['relay_state'], '')
        self.assertEqual(response.context['country'], '')
        self.assertIn('saml_request', response.context)
        self.assertIn('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', response.context['saml_request_xml'])
        self.assertContains(response, '<form action="/CountrySelector" method="post">')
        self.assertContains(response, '<input type="text" name="RelayState" value=""/>')
        self.assertContains(response, '<input type="text" name="country_param" value=""/>')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'
                            .format(response.context['saml_request']))

    def test_post_with_optional_params(self):
        response = self.client.post(self.url, {'Request': '1', 'Country': 'xx', 'RelayState': 'relay123'})
        self.assertEqual(response.context['relay_state'], 'relay123')
        self.assertEqual(response.context['country'], 'xx')
        self.assertIn('saml_request', response.context)
        self.assertIn('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', response.context['saml_request_xml'])
        self.assertContains(response, '<form action="/CountrySelector" method="post">')
        self.assertContains(response, '<input type="text" name="RelayState" value="relay123"/>')
        self.assertContains(response, '<input type="text" name="country_param" value="xx"/>')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'
                            .format(response.context['saml_request']))

    @override_settings(CONNECTOR_SERVICE_PROVIDER=CONNECTOR_SERVICE_PROVIDER_WITHOUT_SIGNATURE)
    def test_post_not_signed(self):
        response = self.client.post(self.url, {'Request': '1'})
        self.assertEqual(response.context['relay_state'], '')
        self.assertEqual(response.context['country'], '')
        self.assertIn('saml_request', response.context)
        self.assertNotIn('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', response.context['saml_request_xml'])
        self.assertContains(response, '<form action="/CountrySelector" method="post">')
        self.assertContains(response, '<input type="text" name="RelayState" value=""/>')
        self.assertContains(response, '<input type="text" name="country_param" value=""/>')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'
                            .format(response.context['saml_request']))


class TestDemoServiceProviderResponseView(SimpleTestCase):
    def setUp(self):
        self.url = reverse('demo-sp-response')

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    def test_post_no_saml_response(self):
        response = self.client.post(self.url)
        self.assertEqual(response.context['saml_response'], None)
        self.assertEqual(response.context['relay_state'], 'None')
        self.assertContains(response, '<code>None</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">None</pre>')

    @override_settings(CONNECTOR_SERVICE_PROVIDER=CONNECTOR_SERVICE_PROVIDER_WITHOUT_SIGNATURE)
    def test_post_without_relay_state(self):
        response = self.client.post(self.url, {'SAMLResponse': b64encode(b'<s></s>').decode('ascii')})
        self.assertEqual(response.context['saml_response'],
                         "<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<s/>\n")
        self.assertEqual(response.context['relay_state'], 'None')
        self.assertContains(response, '<code>None</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">&lt;?xml')

    @override_settings(CONNECTOR_SERVICE_PROVIDER=CONNECTOR_SERVICE_PROVIDER_WITHOUT_SIGNATURE)
    def test_post_with_relay_state(self):
        response = self.client.post(self.url, {'SAMLResponse': b64encode(b'<s></s>').decode('ascii'),
                                               'RelayState': 'xyz'})
        self.assertEqual(response.context['saml_response'],
                         "<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<s/>\n")
        self.assertEqual(response.context['relay_state'], "'xyz'")
        self.assertContains(response, '<code>&#39;xyz&#39;</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">&lt;?xml')

    def test_post_with_signed_saml_response(self):
        with cast(TextIO, (DATA_DIR / 'signed_response_and_assertion.xml').open('r')) as f:
            tree = parse_xml(f.read())
        remove_extra_xml_whitespace(tree)
        saml_response_encoded = b64encode(dump_xml(tree, pretty_print=False)).decode('ascii')
        response = self.client.post(self.url, {'SAMLResponse': saml_response_encoded})
        self.assertIn('\n  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', response.context['saml_response'])
        self.assertIn('\n    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', response.context['saml_response'])
        self.assertEqual(response.context['relay_state'], 'None')
        self.assertContains(response, '<code>None</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">&lt;?xml')
