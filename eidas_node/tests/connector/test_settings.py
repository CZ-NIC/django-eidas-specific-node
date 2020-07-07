from copy import deepcopy
from typing import Any, Dict

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from eidas_node.connector.settings import check_settings
from eidas_node.tests.constants import CERT_FILE, KEY_FILE

CONNECTOR_SERVICE_PROVIDER = {
    'ENDPOINT': '/DemoServiceProviderResponse',
    'REQUEST_ISSUER': 'test-saml-request-issuer',
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'RESPONSE_SIGNATURE': {
        'KEY_FILE': KEY_FILE,
        'CERT_FILE': CERT_FILE,
        'SIGNATURE_METHOD': 'RSA_SHA1',
        'DIGEST_METHOD': 'SHA1',
    },
    'RESPONSE_ENCRYPTION': {},
}  # type: Dict[str, Any]


class TestCheckSettings(SimpleTestCase):
    def test_check_settings_signature_key_and_cert(self):
        with override_settings(CONNECTOR_SERVICE_PROVIDER=CONNECTOR_SERVICE_PROVIDER):
            check_settings()

    def test_check_settings_no_signature(self):
        service_provider = CONNECTOR_SERVICE_PROVIDER.copy()
        service_provider['RESPONSE_SIGNATURE'] = {}
        with override_settings(CONNECTOR_SERVICE_PROVIDER=service_provider):
            check_settings()

    def test_check_settings_signature_no_cert_and_no_key(self):
        service_provider = deepcopy(CONNECTOR_SERVICE_PROVIDER)
        del service_provider['RESPONSE_SIGNATURE']['CERT_FILE']
        del service_provider['RESPONSE_SIGNATURE']['KEY_FILE']
        with override_settings(CONNECTOR_SERVICE_PROVIDER=service_provider):
            check_settings()

    def test_check_settings_signature_cert_and_no_key(self):
        service_provider = deepcopy(CONNECTOR_SERVICE_PROVIDER)
        del service_provider['RESPONSE_SIGNATURE']['KEY_FILE']
        with override_settings(CONNECTOR_SERVICE_PROVIDER=service_provider):
            self.assertRaises(ImproperlyConfigured, check_settings)

    def test_check_settings_signature_key_and_no_cert(self):
        service_provider = deepcopy(CONNECTOR_SERVICE_PROVIDER)
        del service_provider['RESPONSE_SIGNATURE']['CERT_FILE']
        with override_settings(CONNECTOR_SERVICE_PROVIDER=service_provider):
            self.assertRaises(ImproperlyConfigured, check_settings)

    def test_check_settings_track_country_code(self):
        with override_settings(CONNECTOR_TRACK_COUNTRY_CODE=True):
            self.assertRaises(ImproperlyConfigured, check_settings)
