from copy import deepcopy
from typing import Any, Dict

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from eidas_node.proxy_service.settings import check_settings
from eidas_node.tests.constants import CERT_FILE, KEY_FILE

PROXY_SERVICE_IDENTITY_PROVIDER = {
    'ENDPOINT': 'https://test.example.net/identity-provider-endpoint',
    'REQUEST_ISSUER': 'https://test.example.net/saml/idp.xml',
    'REQUEST_SIGNATURE': {
        'KEY_FILE': KEY_FILE,
        'CERT_FILE': CERT_FILE,
        'SIGNATURE_METHOD': 'RSA_SHA1',
        'DIGEST_METHOD': 'SHA1',
    },
}  # type: Dict[str, Any]


class TestCheckSettings(SimpleTestCase):
    def test_check_settings_signature_key_and_cert(self):
        with override_settings(PROXY_SERVICE_IDENTITY_PROVIDER=PROXY_SERVICE_IDENTITY_PROVIDER):
            check_settings()

    def test_check_settings_no_signature(self):
        identity_provider = PROXY_SERVICE_IDENTITY_PROVIDER.copy()
        identity_provider['REQUEST_SIGNATURE'] = {}
        with override_settings(PROXY_SERVICE_IDENTITY_PROVIDER=identity_provider):
            check_settings()

    def test_check_settings_signature_no_cert_and_no_key(self):
        identity_provider = deepcopy(PROXY_SERVICE_IDENTITY_PROVIDER)
        del identity_provider['REQUEST_SIGNATURE']['CERT_FILE']
        del identity_provider['REQUEST_SIGNATURE']['KEY_FILE']
        with override_settings(PROXY_SERVICE_IDENTITY_PROVIDER=identity_provider):
            check_settings()

    def test_check_settings_signature_cert_and_no_key(self):
        identity_provider = deepcopy(PROXY_SERVICE_IDENTITY_PROVIDER)
        del identity_provider['REQUEST_SIGNATURE']['KEY_FILE']
        with override_settings(PROXY_SERVICE_IDENTITY_PROVIDER=identity_provider):
            self.assertRaises(ImproperlyConfigured, check_settings)

    def test_check_settings_signature_key_and_no_cert(self):
        identity_provider = deepcopy(PROXY_SERVICE_IDENTITY_PROVIDER)
        del identity_provider['REQUEST_SIGNATURE']['CERT_FILE']
        with override_settings(PROXY_SERVICE_IDENTITY_PROVIDER=identity_provider):
            self.assertRaises(ImproperlyConfigured, check_settings)
