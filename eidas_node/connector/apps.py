"""Apps of eidas_node.connector."""

from django.apps import AppConfig

from eidas_node.connector.settings import ConnectorSettings


class ConnectorConfig(AppConfig):
    """Configuration of eidas_node.connector app."""

    name = 'eidas_node.connector'

    def ready(self):
        """Run start-up actions."""
        ConnectorSettings.check()
