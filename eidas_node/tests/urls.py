"""Django URLs for unittests."""

from eidas_node.connector.demo import urls as connector_urls
from eidas_node.proxy_service import urls as proxy_service_urls

urlpatterns = connector_urls.urlpatterns + proxy_service_urls.urlpatterns
