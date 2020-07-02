"""Settings of eidas_node.proxy_service."""

from appsettings import (AppSettings, BooleanSetting, DictSetting, NestedDictSetting, PositiveIntegerSetting,
                         StringSetting)
from django.core.exceptions import ImproperlyConfigured

from eidas_node.constants import LevelOfAssurance


class ProxyServiceSettings(AppSettings):
    """eIDAS Node Proxy Service settings."""

    request_token = NestedDictSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
        lifetime=PositiveIntegerSetting(default=10),
    ), required=True)
    response_token = NestedDictSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
    ), required=True)
    identity_provider = NestedDictSetting(settings=dict(
        endpoint=StringSetting(required=True, min_length=1),
        request_issuer=StringSetting(required=True, min_length=1),
        request_signature=NestedDictSetting(
            settings=dict(
                # required=True leads to a strange error:
                # "REQUEST_SIGNATURE setting is missing required item 'REQUEST_SIGNATURE'"
                key_file=StringSetting(min_length=1),
                cert_file=StringSetting(min_length=1),
                signature_method=StringSetting(default='RSA_SHA512', min_length=1),
                digest_method=StringSetting(default='SHA512', min_length=1),
            ),
            # https://github.com/pawamoy/django-appsettings/issues/91
            required=True),
        key_file=StringSetting(),
        cert_file=StringSetting(),
    ), required=True)
    light_storage = NestedDictSetting(settings=dict(
        backend=StringSetting(default='eidas_node.storage.ignite.IgniteStorage', min_length=1),
        options=DictSetting(required=True),
    ), required=True)
    eidas_node = NestedDictSetting(settings=dict(
        proxy_service_response_url=StringSetting(required=True, min_length=1),
        response_issuer=StringSetting(required=True, min_length=1),
    ), required=True)
    levels_of_assurance = DictSetting(key_type=str, value_type=LevelOfAssurance)
    transient_name_id_fallback = BooleanSetting(default=False)
    auxiliary_storage = NestedDictSetting(settings=dict(
        backend=StringSetting(default='eidas_node.storage.ignite.AuxiliaryIgniteStorage', min_length=1),
        options=DictSetting(required=True),
    ))

    class Meta:
        """Metadata."""

        setting_prefix = 'proxy_service_'


PROXY_SERVICE_SETTINGS = ProxyServiceSettings()


def check_settings():
    """Check settings."""
    ProxyServiceSettings.check()
    signature = PROXY_SERVICE_SETTINGS.identity_provider['request_signature']
    # If one of the files is set, the other must be set as well
    if bool(signature.get('key_file')) != bool(signature.get('cert_file')):
        raise ImproperlyConfigured('Both PROXY_SERVICE_IDENTITY_PROVIDER.REQUEST_SIGNATURE.KEY_FILE and '
                                   'PROXY_SERVICE_IDENTITY_PROVIDER.REQUEST_SIGNATURE.CERT_FILE must be set.')

    if PROXY_SERVICE_SETTINGS.transient_name_id_fallback and not PROXY_SERVICE_SETTINGS.auxiliary_storage:
        raise ImproperlyConfigured('PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK is required '
                                   'if PROXY_SERVICE_AUXILIARY_STORAGE is enabled.')
