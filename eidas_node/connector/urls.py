"""URLs of eidas_node.connector."""
from django.urls import path

from eidas_node.connector import views

urlpatterns = [
    path('ServiceProviderRequest', views.ServiceProviderRequestView.as_view(), name='service-provider-request'),
    path('ConnectorResponse', views.ConnectorResponseView.as_view(), name='connector-response'),
]  # type: ignore
