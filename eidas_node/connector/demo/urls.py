"""URLs of eidas_node.connector.demo."""

from django.urls import path

from eidas_node.connector.demo import views
from eidas_node.connector.urls import urlpatterns

urlpatterns += [
    path("DemoServiceProviderRequest", views.DemoServiceProviderRequestView.as_view(), name="demo-sp-request"),
    path("DemoServiceProviderResponse", views.DemoServiceProviderResponseView.as_view(), name="demo-sp-response"),
]  # type: ignore
