"""Modification of views for CZ NIA."""

from django.conf import settings
from lxml.etree import SubElement

from eidas_node.constants import StatusCode, SubStatusCode
from eidas_node.models import LightResponse
from eidas_node.proxy_service.views import IdentityProviderResponseView
from eidas_node.saml import Q_NAMES, SAMLResponse

ATTRIBUTE_PERSON_IDENTIFIER = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"


class CzNiaResponseView(IdentityProviderResponseView):
    """Identity Response view with changes specific to CZ NIA."""

    def get_saml_response(self, *args, **kwargs) -> SAMLResponse:
        """Extract and decrypt a SAML response from POST data."""
        response = super().get_saml_response(*args, **kwargs)

        # Convert a wrong failure response to a correct SAML failure response
        sub_status_code = None
        xml = response.document

        for attribute in xml.findall(".//{}".format(Q_NAMES["saml2:Attribute"])):
            if (
                attribute.get("Name") == "urn:oasis:names:tc:SAML:2.0:protocol/statuscode"
                and len(attribute)
                and attribute[0].tag == Q_NAMES["saml2:AttributeValue"]
                and attribute[0].text == SubStatusCode.AUTHN_FAILED
            ):
                sub_status_code = SubStatusCode.AUTHN_FAILED
                break

        if sub_status_code is not None:
            status_elm = xml.find(".//{}".format(Q_NAMES["saml2p:Status"]))
            assert status_elm is not None  # noqa: S101
            status_code_elm = status_elm[0]
            status_code_elm.attrib["Value"] = StatusCode.RESPONDER
            SubElement(status_code_elm, Q_NAMES["saml2p:StatusCode"], {"Value": sub_status_code})

            assertion = xml.find(".//{}".format(Q_NAMES["saml2:EncryptedAssertion"]))
            if assertion is None:
                assertion = xml.find(".//{}".format(Q_NAMES["saml2:Assertion"]))
            assert assertion is not None  # noqa: S101
            assertion.getparent().remove(assertion)

        return response

    def create_light_response(self, *args, **kwargs) -> LightResponse:
        """Create a light response from SAML response."""
        response = super().create_light_response(*args, **kwargs)

        # Strip wrong prefix
        if getattr(settings, "PROXY_SERVICE_STRIP_PREFIX", False):
            prefix = "CZ/CZ/"
            if response.subject and response.subject.startswith(prefix):
                response.subject = response.subject[len(prefix) :]
            for name, values in (response.attributes or {}).items():
                if name == ATTRIBUTE_PERSON_IDENTIFIER and values and values[0].startswith(prefix):
                    values[0] = values[0][len(prefix) :]
                    break

        return response
