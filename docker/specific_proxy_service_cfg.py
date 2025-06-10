"""Development settings for eidas_node Django app.

DO NOT USE IN PRODUCTION!

See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/
"""

import os
from typing import Any

from eidas_node.tests.constants import DATA_DIR

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_KEY = "5x-fiyyunqio&)a+8%$0fqvqpc1s18n^xj21ftc-ojpu2)jmce"  # noqa: S105
DEBUG = True

ALLOWED_HOSTS = ["*"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "eidas_node.proxy_service.apps.ProxyServiceConfig",
]
MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]
# For czech NIA use 'eidas_node.proxy_service.cznia.urls'
ROOT_URLCONF = "eidas_node.proxy_service.urls"

STATIC_ROOT = "/var/www/ginger/static"
STATIC_URL = "/static/"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.template.context_processors.i18n",
            ]
        },
    }
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

# eIDAS Proxy Service
PROXY_SERVICE_REQUEST_TOKEN: dict[str, Any] = {
    "HASH_ALGORITHM": "sha256",
    "SECRET": "mySecretProxyserviceRequest",
    "ISSUER": "specificCommunicationDefinitionProxyserviceRequest",
    "LIFETIME": 0,  # minutes
}

PROXY_SERVICE_RESPONSE_TOKEN: dict[str, str] = {
    "HASH_ALGORITHM": "sha256",
    "SECRET": "mySecretProxyserviceResponse",
    "ISSUER": "specificCommunicationDefinitionProxyserviceResponse",
}

PROXY_SERVICE_IDENTITY_PROVIDER: dict[str, str] = {
    "ENDPOINT": "https://tnia.eidentita.cz/fpsts/saml2/basic",
    "REQUEST_ISSUER": "http://localhost.localdomain:8000/saml/idp.xml",
    "KEY_SOURCE": "file",
    "KEY_LOCATION": str(DATA_DIR / "key.pem"),
    "CERT_FILE": str(DATA_DIR / "nia-test-cert.pem"),
    "REQUEST_SIGNATURE": {
        "KEY_SOURCE": "file",
        "KEY_LOCATION": str(DATA_DIR / "key.pem"),
        "CERT_FILE": str(DATA_DIR / "cert.pem"),
    },
}

PROXY_SERVICE_LIGHT_STORAGE: dict[str, Any] = {
    "BACKEND": "eidas_node.storage.ignite.IgniteStorage",
    "OPTIONS": {
        "host": "pokuston-m-01.office.nic.cz",
        "port": 10800,
        "request_cache_name": "nodeSpecificProxyserviceRequestCache",
        "response_cache_name": "specificNodeProxyserviceResponseCache",
    },
}

PROXY_SERVICE_EIDAS_NODE: dict[str, str] = {
    "PROXY_SERVICE_RESPONSE_URL": "http://pokuston.office.nic.cz:8888/EidasNode/SpecificProxyServiceResponse",
    "RESPONSE_ISSUER": "specific-proxy-service",
}

# Logging
LOGGING = {
    "version": 1,
    "formatters": {
        "verbose": {"format": "%(asctime)s %(levelname)-8s %(module)s:%(funcName)s:%(lineno)s %(message)s"},
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "eidas_node.proxy_service": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "eidas_node.storage": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
