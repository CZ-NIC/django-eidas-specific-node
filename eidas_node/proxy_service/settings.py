"""Settings of eidas_node.proxy_service."""

from appsettings import AppSettings, DictSetting, NestedSetting, PositiveIntegerSetting, StringSetting


class ProxyServiceSettings(AppSettings):
    """eIDAS Node Proxy Service settings."""

    request_token = NestedSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
        lifetime=PositiveIntegerSetting(default=10),
    ), required=True)
    response_token = NestedSetting(settings=dict(
        hash_algorithm=StringSetting(default='sha256', min_length=1),
        parameter_name=StringSetting(default='token', min_length=1),
        secret=StringSetting(required=True, min_length=1),
        issuer=StringSetting(required=True, min_length=1),
    ), required=True)
    identity_provider = NestedSetting(settings=dict(
        endpoint=StringSetting(required=True, min_length=1),
        request_issuer=StringSetting(required=True, min_length=1),
        key_file=StringSetting(),
    ), required=True)
    light_storage = NestedSetting(settings=dict(
        backend=StringSetting(default='eidas_node.storage.ignite.IgniteStorage', min_length=1),
        options=DictSetting(required=True),
    ), required=True)
    eidas_node = NestedSetting(settings=dict(
        proxy_service_response_url=StringSetting(required=True, min_length=1),
        response_issuer=StringSetting(required=True, min_length=1),
    ), required=True)

    class Meta:
        """Metadata."""

        setting_prefix = 'proxy_service_'


PROXY_SERVICE_SETTINGS = ProxyServiceSettings()
