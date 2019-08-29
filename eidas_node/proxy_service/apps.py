"""Apps of eidas_node.proxy_service."""

from django.apps import AppConfig

from eidas_node.proxy_service.settings import ProxyServiceSettings


class ProxyServiceConfig(AppConfig):
    """Configuration of eidas_node.proxy_service app."""

    name = 'eidas_node.proxy_service'

    def ready(self):
        """Run start-up actions."""
        ProxyServiceSettings.check()
