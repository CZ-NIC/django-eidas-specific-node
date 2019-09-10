"""
Development settings for eidas_node.connector Django app.

DO NOT USE IN PRODUCTION!

See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/
"""

# Security
from typing import Dict, Any

SECRET_KEY = 'secret'
DEBUG = True
ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = (
    'django.contrib.staticfiles',
    'eidas_node.connector.apps.ConnectorConfig',
)
MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
)
ROOT_URLCONF = 'eidas_node.connector.urls'
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

# eIDAS Connector
CONNECTOR_REQUEST_TOKEN = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'mySecretConnectorRequest',
    'ISSUER': 'specificCommunicationDefinitionConnectorRequest',
}  # type: Dict[str, Any]

CONNECTOR_RESPONSE_TOKEN = {
    'HASH_ALGORITHM': 'sha256',
    'SECRET': 'mySecretConnectorResponse',
    'ISSUER': 'specificCommunicationDefinitionConnectorResponse',
    'LIFETIME': 10,  # minutes
}  # type: Dict[str, str]

CONNECTOR_SERVICE_PROVIDER = {
    'ENDPOINT': '/DemoServiceProviderResponse',
    'REQUEST_ISSUER': 'REQUEST_ISSUER',
    'RESPONSE_ISSUER': 'RESPONSE_ISSUER',
}  # type: Dict[str, str]

CONNECTOR_LIGHT_STORAGE = {
    'BACKEND': 'eidas_node.storage.ignite.IgniteStorage',
    'OPTIONS': {
        'host': 'ignite.example.net',
        'port': 10800,
        'request_cache_name': 'specificNodeConnectorRequestCache',
        'response_cache_name': 'nodeSpecificConnectorResponseCache',
    }
}  # type: Dict[str, Any]

CONNECTOR_EIDAS_NODE = {
    'CONNECTOR_REQUEST_URL': 'http://eidasnode.example.net/EidasNode/SpecificConnectorRequest',
    'REQUEST_ISSUER': 'connector-request-issuer',
}  # type: Dict[str, str]

# Logging
LOGGING = {
    'version': 1,
    'formatters': {
        'verbose': {'format': '%(asctime)s %(levelname)-8s %(module)s:%(funcName)s:%(lineno)s %(message)s'},
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
           'handlers': ['console'],
           'level': 'DEBUG',
           'propagate': False,
        },
        'django': {
           'handlers': ['console'],
           'level': 'INFO',
           'propagate': False,
        },
        'eidas_node.connector': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'eidas_node.storage': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
