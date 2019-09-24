"""Django settings for unitests."""
from pathlib import Path
from typing import Any, Dict, List

from eidas_node.tests.warnings import setup_warnings_filter

setup_warnings_filter()

DATA_DIR = Path(__file__).parent / 'data'  # type: Path

SECRET_KEY = 'SECRET'

INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'eidas_node.connector.apps.ConnectorConfig',
    'eidas_node.proxy_service.apps.ProxyServiceConfig',
]  # type: List[str]
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
PROXY_SERVICE_REQUEST_TOKEN = {
    'SECRET': 'request-token-secret',
    'ISSUER': 'request-token-issuer',
    'PARAMETER_NAME': 'test_token',
    'LIFETIME': 10,  # minutes
}  # type: Dict[str, Any]

PROXY_SERVICE_RESPONSE_TOKEN = {
    'SECRET': 'response-token-secret',
    'ISSUER': 'response-token-issuer',
    'PARAMETER_NAME': 'test_token',
}  # type: Dict[str, str]

PROXY_SERVICE_IDENTITY_PROVIDER = {
    'ENDPOINT': 'https://test.example.net/identity-provider-endpoint',
    'REQUEST_ISSUER': 'https://test.example.net/saml/idp.xml',
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'KEY_FILE': str(DATA_DIR / 'key.pem'),
}  # type: Dict[str, str]

PROXY_SERVICE_LIGHT_STORAGE = {
    'OPTIONS': {
        'host': 'test.example.net',
        'port': 1234,
        'request_cache_name': 'test-proxy-service-request-cache',
        'response_cache_name': 'test-proxy-service-response-cache',
        'timeout': 66,
    }
}  # type: Dict[str, Any]

PROXY_SERVICE_EIDAS_NODE = {
    'PROXY_SERVICE_RESPONSE_URL': 'https://test.example.net/SpecificProxyServiceResponse',
    'REQUEST_ISSUER': 'test-light-request-issuer',
    'RESPONSE_ISSUER': 'https://test.example.net/node-proxy-service-response',
}  # type: Dict[str, str]

# eIDAS Connector
CONNECTOR_REQUEST_TOKEN = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'request-token-secret',
    'ISSUER': 'request-token-issuer',
    'PARAMETER_NAME': 'test_request_token',
}  # type: Dict[str, Any]

CONNECTOR_RESPONSE_TOKEN = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'response-token-secret',
    'ISSUER': 'response-token-issuer',
    'PARAMETER_NAME': 'test_response_token',
    'LIFETIME': 10,  # minutes
}  # type: Dict[str, Any]

CONNECTOR_SERVICE_PROVIDER = {
    'ENDPOINT': '/DemoServiceProviderResponse',
    'REQUEST_ISSUER': 'test-saml-request-issuer',
    'RESPONSE_ISSUER': 'test-saml-response-issuer',
    'COUNTRY_PARAMETER': 'country_param',
}  # type: Dict[str, str]

CONNECTOR_LIGHT_STORAGE = {
    'BACKEND': 'eidas_node.storage.ignite.IgniteStorage',
    'OPTIONS': {
        'host': 'test.example.net',
        'port': 1234,
        'request_cache_name': 'test-connector-request-cache',
        'response_cache_name': 'test-connector-response-cache',
        'timeout': 66,
    }
}  # type: Dict[str, Any]

CONNECTOR_EIDAS_NODE = {
    'CONNECTOR_REQUEST_URL': 'http://test.example.net/SpecificConnectorRequest',
    'REQUEST_ISSUER': 'test-connector-request-issuer',
}  # type: Dict[str, str]

CONNECTOR_SELECTOR_COUNTRIES = [('CA', 'Test Country'), ('CZ', 'Another Country')]
