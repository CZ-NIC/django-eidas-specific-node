"""URLs of eidas_node.connector."""
from django.urls import path

from eidas_node.connector import views

urlpatterns = [
    path('CitizenCountrySelector', views.CitizenCountrySelectorView.as_view(), name='citizen-country-selector'),
    path('ServiceProviderRequest', views.ServiceProviderRequestView.as_view(), name='service-provider-request'),
    path('ConnectorResponse', views.ConnectorResponseView.as_view(), name='connector-response'),
]  # type: ignore
