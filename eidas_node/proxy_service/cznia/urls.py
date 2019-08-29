"""URLs for CZ NIA changes."""
from django.urls import path

from eidas_node.proxy_service.cznia.views import CzNiaResponseView
from eidas_node.proxy_service.views import ProxyServiceRequestView

urlpatterns = [
    path('ProxyServiceRequest', ProxyServiceRequestView.as_view(), name='proxy-service-request'),
    path('IdentityProviderResponse', CzNiaResponseView.as_view(), name='identity-provider-response'),
]  # type: ignore
