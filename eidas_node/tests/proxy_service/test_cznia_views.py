from base64 import b64encode
from copy import deepcopy
from typing import BinaryIO, cast
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse

from eidas_node.models import LightResponse, Status
from eidas_node.proxy_service.cznia.views import CzNiaResponseView
from eidas_node.proxy_service.views import IdentityProviderResponseView
from eidas_node.tests.proxy_service.test_views import DATA_DIR
from eidas_node.tests.test_models import LIGHT_RESPONSE_DICT
from eidas_node.xml import dump_xml

PERSON_ID = 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'


@override_settings(ROOT_URLCONF='eidas_node.proxy_service.cznia.urls')
class TestCzNiaResponseView(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse('identity-provider-response')

    def get_light_response_data(self, subject_id: str) -> dict:
        data = deepcopy(LIGHT_RESPONSE_DICT)
        data['status'] = Status(**data['status'])
        data['subject'] = subject_id
        data['attributes'][PERSON_ID][0] = subject_id
        return data

    def test_get_saml_response_fix_not_needed(self):
        self.maxDiff = None

        for name in 'saml_response_failed.xml', 'saml_response.xml':
            with self.subTest(name=name):
                with cast(BinaryIO, (DATA_DIR / name).open('rb')) as f:
                    saml_response_xml = f.read()

                view = CzNiaResponseView()
                view.request = self.factory.post(self.url,
                                                 {'SAMLResponse': b64encode(saml_response_xml).decode('ascii')})
                saml_response = view.get_saml_response(None, None, None)
                self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'),
                                    saml_response_xml.decode('utf-8'))

    def test_get_saml_response_fix_failure_response(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_failed_nia_fixed.xml').open('rb')) as f:
            saml_response_xml_fixed = f.read()

        for name in 'saml_response_failed_nia.xml', 'saml_response_failed_nia_decrypted.xml':
            with self.subTest(name=name):
                with cast(BinaryIO, (DATA_DIR / name).open('rb')) as f:
                    saml_response_xml = f.read()

                view = CzNiaResponseView()
                view.request = self.factory.post(self.url,
                                                 {'SAMLResponse': b64encode(saml_response_xml).decode('ascii')})
                saml_response = view.get_saml_response(None, None, None)
                self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'),
                                    saml_response_xml_fixed.decode('utf-8'))

    @override_settings(PROXY_SERVICE_STRIP_PREFIX=False)
    def test_create_light_response_do_not_strip_prefix(self):
        data = self.get_light_response_data('CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9')
        response = LightResponse(**deepcopy(data))

        with patch.object(IdentityProviderResponseView, 'create_light_response', return_value=response):
            view = CzNiaResponseView()
            self.assertEqual(view.create_light_response(), LightResponse(**data))

    @override_settings(PROXY_SERVICE_STRIP_PREFIX=True)
    def test_create_light_response_strip_prefix_not_needed(self):
        data = self.get_light_response_data('CA/CA/ff70c9dd-6a05-4068-aaa2-b57be4f328e9')
        response = LightResponse(**deepcopy(data))
        self.maxDiff = None
        with patch.object(IdentityProviderResponseView, 'create_light_response', return_value=response):
            view = CzNiaResponseView()
            self.assertEqual(view.create_light_response(), LightResponse(**data))

    @override_settings(PROXY_SERVICE_STRIP_PREFIX=True)
    def test_create_light_response_strip_prefix_needed(self):
        response = LightResponse(**self.get_light_response_data('CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9'))
        self.maxDiff = None
        with patch.object(IdentityProviderResponseView, 'create_light_response', return_value=response):
            view = CzNiaResponseView()
            self.assertEqual(view.create_light_response(),
                             LightResponse(**self.get_light_response_data('ff70c9dd-6a05-4068-aaa2-b57be4f328e9')))
