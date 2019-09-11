from base64 import b64encode

from django.test.testcases import SimpleTestCase
from django.urls import reverse


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
            self.assertEquals(response.status_code, 400)

    def test_post_without_optional_params(self):
        response = self.client.post(self.url, {'Request': '1'})
        self.assertEquals(response.context['relay_state'], '')
        self.assertEquals(response.context['country'], '')
        self.assertIn('saml_request', response.context)
        self.assertContains(response, '<form action="/CountrySelector" method="post">')
        self.assertContains(response, '<input type="text" name="RelayState" value=""/>')
        self.assertContains(response, '<input type="text" name="country_param" value=""/>')
        self.assertContains(response, '<input type="hidden" name="SAMLRequest" value="{}"/>'
                            .format(response.context['saml_request']))

    def test_post_with_optional_params(self):
        response = self.client.post(self.url, {'Request': '1', 'Country': 'xx', 'RelayState': 'relay123'})
        self.assertEquals(response.context['relay_state'], 'relay123')
        self.assertEquals(response.context['country'], 'xx')
        self.assertIn('saml_request', response.context)
        self.assertContains(response, '<form action="/CountrySelector" method="post">')
        self.assertContains(response, '<input type="text" name="RelayState" value="relay123"/>')
        self.assertContains(response, '<input type="text" name="country_param" value="xx"/>')
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

    def test_post_without_relay_state(self):
        response = self.client.post(self.url, {'SAMLResponse': b64encode(b'...').decode('ascii')})
        self.assertEqual(response.context['saml_response'], '...')
        self.assertEqual(response.context['relay_state'], 'None')
        self.assertContains(response, '<code>None</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">...</pre>')

    def test_post_with_relay_state(self):
        response = self.client.post(self.url, {'SAMLResponse': b64encode(b'...').decode('ascii'), 'RelayState': 'xyz'})
        self.assertEqual(response.context['saml_response'], '...')
        self.assertEqual(response.context['relay_state'], "'xyz'")
        self.assertContains(response, '<code>&#39;xyz&#39;</code>')
        self.assertContains(response, '<pre style="white-space: pre-wrap;">...</pre>')
