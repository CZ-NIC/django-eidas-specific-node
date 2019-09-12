"""Settings of eidas_node.connector."""

from appsettings import AppSettings, DictSetting, NestedSetting, PositiveIntegerSetting, StringSetting


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
        request_issuer=StringSetting(required=True, min_length=1),
        response_issuer=StringSetting(required=True, min_length=1),
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

    class Meta:
        """Metadata."""

        setting_prefix = 'connector_'


CONNECTOR_SETTINGS = ConnectorSettings()
