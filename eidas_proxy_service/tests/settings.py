"""Django settings for unitests."""

SECRET_KEY = 'SECRET'

INSTALLED_APPS = [
    'eidas_proxy_service.apps.EidasProxyServiceConfig',
]
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
]
ROOT_URLCONF = 'eidas_proxy_service.urls'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
