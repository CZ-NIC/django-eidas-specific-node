"""URLs of eidas_node.proxy_service."""
from django.urls import path

from eidas_node.proxy_service import views

urlpatterns = [
    path('ProxyServiceRequest', views.ProxyServiceRequestView.as_view(), name='proxy-service-request'),
    path('IdentityProviderResponse', views.IdentityProviderResponseView.as_view(), name='identity-provider-response'),
]  # type: ignore
