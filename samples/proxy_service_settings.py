"""Development settings for eidas_node.proxy_service Django app.

DO NOT USE IN PRODUCTION!

See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/
"""

# Security
SECRET_KEY = "secret"  # noqa: S105
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
ROOT_URLCONF = "eidas_node.proxy_service.urls"

STATIC_ROOT = "/var/www/eidas-node-proxy-service/static"
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

# eIDAS Proxy Service
PROXY_SERVICE_REQUEST_TOKEN = {
    "HASH_ALGORITHM": "sha256",
    "SECRET": "mySecretProxyserviceRequest",
    "ISSUER": "specificCommunicationDefinitionProxyserviceRequest",
    "LIFETIME": 10,  # minutes
}

PROXY_SERVICE_RESPONSE_TOKEN = {
    "HASH_ALGORITHM": "sha256",
    "SECRET": "mySecretProxyserviceResponse",
    "ISSUER": "specificCommunicationDefinitionProxyserviceResponse",
}

PROXY_SERVICE_LIGHT_STORAGE = {
    "BACKEND": "eidas_node.storage.ignite.IgniteStorage",
    "OPTIONS": {
        "host": "ignite.example.net",
        "port": 10800,
        "request_cache_name": "nodeSpecificProxyserviceRequestCache",
        "response_cache_name": "specificNodeProxyserviceResponseCache",
    },
}

PROXY_SERVICE_IDENTITY_PROVIDER = {
    "ENDPOINT": "https://tnia.eidentita.cz/fpsts/saml2/basic",
    "REQUEST_ISSUER": "http://eidasproxyservice.example.net/saml/idp.xml",
    "KEY_SOURCE": "file",
    "KEY_LOCATION": "/etc/eidas-proxy-service/key.pem",
}

PROXY_SERVICE_EIDAS_NODE = {
    "PROXY_SERVICE_RESPONSE_URL": "http://eidasnode.example.net/EidasNode/SpecificProxyServiceResponse",
    "RESPONSE_ISSUER": "http://eidasproxyservice.example.net",
}
