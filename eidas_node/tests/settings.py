"""Django settings for unitests."""
from typing import List

SECRET_KEY = 'SECRET'

INSTALLED_APPS = []  # type: List[str]
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
]
ROOT_URLCONF = 'eidas_node.tests.urls'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
