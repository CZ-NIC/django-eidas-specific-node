"""Views of eidas_node.connector.demo."""

import logging
from base64 import b64decode, b64encode
from collections import namedtuple
from datetime import datetime
from typing import Optional

from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBadRequest
from django.urls import reverse
from django.views.generic import TemplateView

from eidas_node.attributes import EIDAS_NATURAL_PERSON_ATTRIBUTES, MANDATORY_ATTRIBUTE_NAMES
from eidas_node.connector.settings import CONNECTOR_SETTINGS
from eidas_node.constants import LevelOfAssurance, NameIdFormat, ServiceProviderType
from eidas_node.models import LightRequest
from eidas_node.saml import SAMLRequest, SAMLResponse
from eidas_node.xml import create_xml_uuid, dump_xml, parse_xml

LOGGER = logging.getLogger("eidas_node.connector")

Preset = namedtuple("Preset", "label,id_format,attributes")

PRESETS = [
    Preset(*args)
    for args in [
        (
            "mandatory attributes, persistent name id",
            NameIdFormat.PERSISTENT,
            MANDATORY_ATTRIBUTE_NAMES,
        ),
        (
            "mandatory attributes, transient name id",
            NameIdFormat.TRANSIENT,
            MANDATORY_ATTRIBUTE_NAMES,
        ),
        (
            "mandatory attributes, unspecified name id",
            NameIdFormat.UNSPECIFIED,
            MANDATORY_ATTRIBUTE_NAMES,
        ),
        (
            "natural person attributes, persistent name id",
            NameIdFormat.PERSISTENT,
            [attribute.name_uri for attribute in EIDAS_NATURAL_PERSON_ATTRIBUTES],
        ),
    ]
]

COUNTRY_PLACEHOLDER = "..."


class DemoServiceProviderRequestView(TemplateView):
    """Demo Service Provider's view to create and send a SAML Request to Specific Connector."""

    template_name = "eidas_node/connector/demo/service_provider_request.html"
    saml_request: Optional[SAMLRequest] = None

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        try:
            preset = PRESETS[int(request.POST.get("Request", ""))]
        except (ValueError, KeyError):
            return HttpResponseBadRequest()

        light_request = LightRequest(
            id=create_xml_uuid(),
            issuer=CONNECTOR_SETTINGS.service_provider["request_issuer"],
            level_of_assurance=LevelOfAssurance.LOW,
            provider_name="Demo Service Provider",
            sp_type=ServiceProviderType.PUBLIC,
            relay_state=request.POST.get("RelayState") or None,
            sp_country_code="EU",
            citizen_country_code=request.POST.get("Country"),
            name_id_format=preset.id_format,
            requested_attributes={name: [] for name in preset.attributes},
        )
        if not light_request.citizen_country_code:
            # Use a placeholder to get through light request validation.
            light_request.citizen_country_code = COUNTRY_PLACEHOLDER
        self.saml_request = SAMLRequest.from_light_request(light_request, "/dest", datetime.utcnow())
        signature_options = CONNECTOR_SETTINGS.service_provider["response_signature"]
        if (
            signature_options
            and signature_options.get("key_source")
            and signature_options.get("key_location")
            and signature_options.get("cert_file")
        ):
            self.saml_request.sign_request(**signature_options)
        return self.get(request)

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)

        if self.saml_request:
            context["connector_endpoint"] = reverse("country-selector")
            encoded_saml_request = b64encode(dump_xml(self.saml_request.document, pretty_print=False)).decode("ascii")
            context["saml_request"] = encoded_saml_request
            context["saml_request_xml"] = dump_xml(self.saml_request.document).decode("ascii")
            relay_state = self.saml_request.relay_state
            country = self.saml_request.citizen_country_code
        else:
            country = None
            relay_state = None

        context["presets"] = [(i, preset.label) for i, preset in enumerate(PRESETS)]
        context["relay_state"] = relay_state or ""
        context["country"] = country if country and country != COUNTRY_PLACEHOLDER else ""
        context["country_parameter"] = CONNECTOR_SETTINGS.service_provider["country_parameter"]
        return context


class DemoServiceProviderResponseView(TemplateView):
    """Demo Service Provider's view to show a SAML Response returned from Specific Connector."""

    http_method_names = ["post"]
    template_name = "eidas_node/connector/demo/service_provider_response.html"
    saml_response: Optional[str] = None
    relay_state: Optional[str] = None

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        saml_response_xml = b64decode(self.request.POST.get("SAMLResponse", "").encode("ascii")).decode("utf-8")
        if saml_response_xml:
            # Verify signatures
            cert_file = (CONNECTOR_SETTINGS.service_provider["response_signature"] or {}).get("cert_file")
            if cert_file:
                response = SAMLResponse(parse_xml(saml_response_xml))
                response.verify_response(cert_file)
                response.verify_assertion(cert_file)

            # Reformat with pretty printing for display
            saml_response_xml = dump_xml(parse_xml(saml_response_xml)).decode("utf-8")

        self.saml_response = saml_response_xml
        self.relay_state = self.request.POST.get("RelayState")
        return self.get(request)

    def get_context_data(self, **kwargs):
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context["saml_response"] = self.saml_response or None
        context["relay_state"] = repr(self.relay_state)
        return context
