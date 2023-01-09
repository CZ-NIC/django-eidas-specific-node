"""Django settings for unitests."""
from typing import Any, Dict, List

from eidas_node.tests.constants import CERT_FILE, KEY_FILE
from eidas_node.tests.warnings import setup_warnings_filter

setup_warnings_filter()


SECRET_KEY = 'SECRET'

INSTALLED_APPS: List[str] = [
    'django.contrib.staticfiles',
    'eidas_node.connector.apps.ConnectorConfig',
    'eidas_node.proxy_service.apps.ProxyServiceConfig',
]
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
]
ROOT_URLCONF = 'eidas_node.tests.urls'

STATIC_URL = '/static/'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.template.context_processors.i18n',
            ]
        }
    }
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# eIDAS Proxy Service
PROXY_SERVICE_REQUEST_TOKEN: Dict[str, Any] = {
    'SECRET': 'request-token-secret',
    'ISSUER': 'request-token-issuer',
    'PARAMETER_NAME': 'test_token',
    'LIFETIME': 10,  # minutes
}

PROXY_SERVICE_RESPONSE_TOKEN: Dict[str, str] = {
    'SECRET': 'response-token-secret',
    'ISSUER': 'response-token-issuer',
    'PARAMETER_NAME': 'test_token',
}

PROXY_SERVICE_IDENTITY_PROVIDER: Dict[str, Any] = {
    'ENDPOINT': 'https://test.example.net/identity-provider-endpoint',
    'REQUEST_ISSUER': 'https://test.example.net/saml/idp.xml',
    'REQUEST_SIGNATURE': {
        'KEY_FILE': KEY_FILE,
        'CERT_FILE': CERT_FILE,
        'SIGNATURE_METHOD': 'RSA_SHA1',
        'DIGEST_METHOD': 'SHA1',
    },
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'KEY_FILE': KEY_FILE,
}

PROXY_SERVICE_LIGHT_STORAGE: Dict[str, Any] = {
    'OPTIONS': {
        'host': 'test.example.net',
        'port': 1234,
        'request_cache_name': 'test-proxy-service-request-cache',
        'response_cache_name': 'test-proxy-service-response-cache',
        'timeout': 66,
    }
}

PROXY_SERVICE_EIDAS_NODE: Dict[str, str] = {
    'PROXY_SERVICE_RESPONSE_URL': 'https://test.example.net/SpecificProxyServiceResponse',
    'REQUEST_ISSUER': 'test-light-request-issuer',
    'RESPONSE_ISSUER': 'https://test.example.net/node-proxy-service-response',
}

# eIDAS Connector
CONNECTOR_REQUEST_TOKEN: Dict[str, Any] = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'request-token-secret',
    'ISSUER': 'request-token-issuer',
    'PARAMETER_NAME': 'test_request_token',
}

CONNECTOR_RESPONSE_TOKEN: Dict[str, Any] = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'response-token-secret',
    'ISSUER': 'response-token-issuer',
    'PARAMETER_NAME': 'test_response_token',
    'LIFETIME': 10,  # minutes
}

CONNECTOR_SERVICE_PROVIDER: Dict[str, Any] = {
    'ENDPOINT': '/DemoServiceProviderResponse',
    'CERT_FILE': CERT_FILE,
    'REQUEST_ISSUER': 'test-saml-request-issuer',
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'RESPONSE_SIGNATURE': {
        'KEY_FILE': KEY_FILE,
        'CERT_FILE': CERT_FILE,
        'SIGNATURE_METHOD': 'RSA_SHA1',
        'DIGEST_METHOD': 'SHA1',
    },
    'COUNTRY_PARAMETER': 'country_param',
    'RESPONSE_ENCRYPTION': {},
}

CONNECTOR_LIGHT_STORAGE: Dict[str, Any] = {
    'BACKEND': 'eidas_node.storage.ignite.IgniteStorage',
    'OPTIONS': {
        'host': 'test.example.net',
        'port': 1234,
        'request_cache_name': 'test-connector-request-cache',
        'response_cache_name': 'test-connector-response-cache',
        'timeout': 66,
    }
}

CONNECTOR_EIDAS_NODE: Dict[str, str] = {
    'CONNECTOR_REQUEST_URL': 'http://test.example.net/SpecificConnectorRequest',
    'REQUEST_ISSUER': 'test-connector-request-issuer',
}

CONNECTOR_SELECTOR_COUNTRIES = [('CA', 'Test Country'), ('CZ', 'Another Country')]
