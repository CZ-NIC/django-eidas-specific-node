"""URLs of eidas_node.connector."""

from django.urls import path

from eidas_node.connector import views

urlpatterns = [
    path("CountrySelector", views.CountrySelectorView.as_view(), name="country-selector"),
    path("ServiceProviderRequest", views.ServiceProviderRequestView.as_view(), name="service-provider-request"),
    path("ConnectorResponse", views.ConnectorResponseView.as_view(), name="connector-response"),
]  # type: ignore
