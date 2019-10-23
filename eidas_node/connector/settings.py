"""Settings of eidas_node.connector."""

from appsettings import AppSettings, DictSetting, IterableSetting, NestedSetting, PositiveIntegerSetting, StringSetting
from django.core.exceptions import ImproperlyConfigured

from eidas_node.attributes import ATTRIBUTE_MAP

DEFAULT_COUNTRIES = [
    # Country code, name
    ('AT', 'Austria'),
    ('BE', 'Belgium'),
    ('BG', 'Bulgaria'),
    ('CY', 'Republic of Cyprus'),
    ('CZ', 'Czech Republic'),
    ('DE', 'Germany'),
    ('DK', 'Denmark'),
    ('EE', 'Estonia'),
    ('ES', 'Spain'),
    ('FI', 'Finland'),
    ('FR', 'France'),
    ('GB', 'Great Britain'),
    ('GR', 'Greece'),
    ('HR', 'Croatia'),
    ('HU', 'Hungary'),
    ('IE', 'Republic of Ireland'),
    ('IS', 'Iceland'),
    ('IT', 'Italy'),
    ('LI', 'Liechtenstein'),
    ('LT', 'Lithuania'),
    ('LU', 'Luxembourg'),
    ('LV', 'Latvia'),
    ('MT', 'Malta'),
    ('NL', 'Netherlands'),
    ('NO', 'Norway'),
    ('PL', 'Poland'),
    ('PT', 'Portugal'),
    ('RO', 'Romania'),
    ('SE', 'Sweden'),
    ('SI', 'Slovenia'),
    ('SK', 'Slovakia'),
]


class ConnectorSettings(AppSettings):
    """eIDAS Node Connector settings."""

    request_token = NestedSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
    ), required=True)
    response_token = NestedSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
        lifetime=PositiveIntegerSetting(default=10),
    ), required=True)
    service_provider = NestedSetting(settings=dict(
        endpoint=StringSetting(required=True, min_length=1),
        cert_file=StringSetting(min_length=1),
        request_issuer=StringSetting(required=True, min_length=1),
        response_issuer=StringSetting(required=True, min_length=1),
        response_signature=NestedSetting(
            settings=dict(
                # required=True leads to a strange error:
                # "RESPONSE_SIGNATURE setting is missing required item 'RESPONSE_SIGNATURE'"
                key_file=StringSetting(min_length=1),
                cert_file=StringSetting(min_length=1),
                signature_method=StringSetting(default='RSA_SHA512', min_length=1),
                digest_method=StringSetting(default='SHA512', min_length=1),
            )),
        response_validity=PositiveIntegerSetting(default=10),
        country_parameter=StringSetting(default='country', min_length=1),
    ), required=True)
    light_storage = NestedSetting(settings=dict(
        backend=StringSetting(default='eidas_node.storage.ignite.IgniteStorage', min_length=1),
        options=DictSetting(required=True),
    ), required=True)
    eidas_node = NestedSetting(settings=dict(
        connector_request_url=StringSetting(required=True, min_length=1),
        request_issuer=StringSetting(required=True, min_length=1),
    ), required=True)
    allowed_attributes = IterableSetting(default=set(ATTRIBUTE_MAP))
    selector_countries = IterableSetting(default=DEFAULT_COUNTRIES, min_length=1)

    class Meta:
        """Metadata."""

        setting_prefix = 'connector_'


CONNECTOR_SETTINGS = ConnectorSettings()


def check_settings():
    """Check settings."""
    ConnectorSettings.check()
    signature = CONNECTOR_SETTINGS.service_provider['response_signature']
    # If one of the files is set, the other must be set as well
    if bool(signature.get('key_file')) != bool(signature.get('cert_file')):
        raise ImproperlyConfigured('Both CONNECTOR_SERVICE_PROVIDER.RESPONSE_SIGNATURE.KEY_FILE and '
                                   'CONNECTOR_SERVICE_PROVIDER.RESPONSE_SIGNATURE.CERT_FILE must be set.')
