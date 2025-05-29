"""Views of eidas_node.proxy_service."""

import logging
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, cast
from uuid import uuid4

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.template.loader import select_template
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from lxml.etree import XMLSyntaxError

from eidas_node.constants import TOKEN_ID_PREFIX, LevelOfAssurance, NameIdFormat
from eidas_node.errors import EidasNodeError, ParseError, SecurityError
from eidas_node.models import LightRequest, LightResponse, LightToken, Status
from eidas_node.proxy_service.settings import PROXY_SERVICE_SETTINGS
from eidas_node.saml import SAMLRequest, SAMLResponse
from eidas_node.storage import LightStorage, get_auxiliary_storage
from eidas_node.utils import WrappedSeries, import_from_module
from eidas_node.xml import create_xml_uuid, dump_xml, parse_xml

LOGGER = logging.getLogger("eidas_node.proxy_service")
LOG_ID_SERIES = WrappedSeries()


class ProxyServiceRequestView(TemplateView):
    """
    Forward service provider's request to an identity provider.

    eIDAS Generic Proxy Service provides the service provider's request as a light request.
    """

    http_method_names = ["post"]
    template_name = "eidas_node/proxy_service/proxy_service_request.html"
    error: Optional[str] = None
    storage: Optional[LightStorage] = None
    light_token: Optional[LightToken] = None
    light_request: Optional[LightRequest] = None
    saml_request: Optional[SAMLRequest] = None
    log_id: int = 0
    auxiliary_data: Optional[Dict[str, Any]] = None

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        self.auxiliary_data = {}
        self.log_id = LOG_ID_SERIES.next()
        try:
            token_settings = PROXY_SERVICE_SETTINGS.request_token
            self.light_token = self.get_light_token(
                token_settings["parameter_name"],
                token_settings["issuer"],
                token_settings["hash_algorithm"],
                token_settings["secret"],
                token_settings["lifetime"],
            )
            LOGGER.debug("Light Token: %s", self.light_token)
            self.storage = self.get_light_storage(
                PROXY_SERVICE_SETTINGS.light_storage["backend"], PROXY_SERVICE_SETTINGS.light_storage["options"]
            )
            self.light_request = self.get_light_request()
            LOGGER.debug("Light Request: %s", self.light_request)

            if PROXY_SERVICE_SETTINGS.transient_name_id_fallback and self.light_request.name_id_format is not None:
                self.auxiliary_data["name_id_format"] = self.light_request.name_id_format.value

            if PROXY_SERVICE_SETTINGS.track_country_code:
                self.auxiliary_data["citizen_country"] = self.light_request.citizen_country_code
                self.auxiliary_data["origin_country"] = self.light_request.sp_country_code

            LOGGER.info(
                "Received Light Request: id=%r, citizen_country=%r, origin_country=%r.",
                self.light_request.id,
                self.light_request.citizen_country_code,
                self.light_request.sp_country_code,
            )

            self.saml_request = self.create_saml_request(
                PROXY_SERVICE_SETTINGS.identity_provider["request_issuer"],
                PROXY_SERVICE_SETTINGS.identity_provider["request_signature"],
            )
            LOGGER.debug("SAML Request: %s", self.saml_request)

            # Store auxiliary data only if there are any. No data yield an empty dict on retrieval.
            if self.auxiliary_data:
                auxiliary_storage = get_auxiliary_storage(
                    PROXY_SERVICE_SETTINGS.auxiliary_storage["backend"],
                    PROXY_SERVICE_SETTINGS.auxiliary_storage["options"],
                )
                assert self.light_request.id is not None
                auxiliary_storage.put(self.light_request.id, self.auxiliary_data)

        except EidasNodeError as e:
            LOGGER.exception("[#%r] Bad proxy service request: %s", self.log_id, e)
            self.error = _("Bad proxy service request.")
            return HttpResponseBadRequest(
                select_template(self.get_template_names()).render(self.get_context_data(), self.request)
            )
        return super().get(request)

    def get_light_token(
        self, parameter_name: str, issuer: str, hash_algorithm: str, secret: str, lifetime: Optional[int] = None
    ) -> LightToken:
        """
        Retrieve and verify a light token according to token settings.

        :param parameter_name: The name of HTTP POST parameter to get the token from.
        :param issuer: Token issuer.
        :param hash_algorithm: A hashlib hash algorithm.
        :param secret: A secret shared between communication parties.
        :param lifetime: Lifetime of the token (in minutes) until its expiration.
        :return: A decoded LightToken.
        :raise ParseError: If the token is malformed and cannot be decoded.
        :raise ValidationError: If the token can be decoded but model validation fails.
        :raise SecurityError: If the token digest or issuer is invalid or the token has expired.
        """
        encoded_token = self.request.POST.get(parameter_name, "").encode("utf-8")
        LOGGER.info("[#%r] Received encoded light token: %r", self.log_id, encoded_token)
        token = LightToken.decode(encoded_token, hash_algorithm, secret)
        LOGGER.info("[#%r] Decoded light token: id=%r, issuer=%r", self.log_id, token.id, token.issuer)
        if token.issuer != issuer:
            raise SecurityError("Invalid token issuer.")
        if lifetime and token.created + timedelta(minutes=lifetime) < datetime.now():
            raise SecurityError("Token has expired.")
        return token

    def get_light_storage(self, backend: str, options: Dict[str, Any]) -> LightStorage:
        """
        Create a light storage instance.

        :param backend: A fully qualified name of the backend class.
        :param options: The options to pass to the backend.
        :return: A light storage instance.
        """
        return import_from_module(backend)(**options)

    def get_light_request(self) -> LightRequest:
        """
        Get a light request.

        :return: A light request.
        :raise SecurityError: If the request is not found.
        """
        assert self.storage is not None
        assert self.light_token is not None
        request = self.storage.pop_light_request(self.light_token.id)
        if request is None:
            raise SecurityError("Request not found in light storage.")
        return request

    def create_saml_request(self, issuer: str, signature_options: Optional[Dict[str, str]]) -> SAMLRequest:
        """
        Create a SAML request from a light request.

        :param issuer: Issuer of the SAML request.
        :param signature_options: Optional options to create a signed request: `key_source`, `key_location`,
            `cert_file`, `signature_method` abd `digest_method`.
        :return: A SAML request.
        """
        assert self.light_request is not None

        # Replace the original issuer with our issuer registered at the Identity Provider.
        self.light_request.issuer = issuer

        destination = self.request.build_absolute_uri(reverse("identity-provider-response"))
        saml_request = SAMLRequest.from_light_request(self.light_request, destination, datetime.utcnow())
        LOGGER.info("[#%r] Created SAML request: id=%r, issuer=%r", self.log_id, saml_request.id, saml_request.issuer)

        if (
            signature_options
            and signature_options.get("key_source")
            and signature_options.get("key_location")
            and signature_options.get("cert_file")
        ):
            saml_request.sign_request(**signature_options)
        return saml_request

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context["error"] = self.error

        if self.saml_request:
            encoded_saml_request = b64encode(dump_xml(self.saml_request.document, pretty_print=False)).decode("ascii")
            context["identity_provider_endpoint"] = PROXY_SERVICE_SETTINGS.identity_provider["endpoint"]
            context["saml_request"] = encoded_saml_request
            context["relay_state"] = self.saml_request.relay_state or ""
        return context


class IdentityProviderResponseView(TemplateView):
    """
    Forward an identity provider's response to a service provider.

    eIDAS Generic Proxy Service expect the identity provider's response as a light response.
    """

    http_method_names = ["post"]
    template_name = "eidas_node/proxy_service/identity_provider_response.html"
    error: Optional[str] = None
    storage: Optional[LightStorage] = None
    saml_response: Optional[SAMLResponse] = None
    light_response: Optional[LightResponse] = None
    light_token: Optional[LightToken] = None
    encoded_token: Optional[str] = None
    log_id: int = 0
    auxiliary_data: Optional[Dict[str, Any]] = None

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        self.log_id = LOG_ID_SERIES.next()
        try:
            self.saml_response = self.get_saml_response(
                PROXY_SERVICE_SETTINGS.identity_provider.get("key_source"),
                PROXY_SERVICE_SETTINGS.identity_provider.get("key_location"),
                PROXY_SERVICE_SETTINGS.identity_provider.get("cert_file"),
            )
            LOGGER.debug("SAML Response: %s", self.saml_response)

            # Load auxiliary data if the storage is defined. Use an empty dict as a default value.
            request_id = self.saml_response.in_response_to_id
            if request_id and PROXY_SERVICE_SETTINGS.auxiliary_storage:
                auxiliary_storage = get_auxiliary_storage(
                    PROXY_SERVICE_SETTINGS.auxiliary_storage["backend"],
                    PROXY_SERVICE_SETTINGS.auxiliary_storage["options"],
                )
                self.auxiliary_data = auxiliary_storage.pop(request_id) or {}
            else:
                self.auxiliary_data = {}

            self.storage = self.get_light_storage(
                PROXY_SERVICE_SETTINGS.light_storage["backend"], PROXY_SERVICE_SETTINGS.light_storage["options"]
            )
            token_settings = PROXY_SERVICE_SETTINGS.response_token
            self.light_response = self.create_light_response(
                PROXY_SERVICE_SETTINGS.eidas_node["response_issuer"], PROXY_SERVICE_SETTINGS.levels_of_assurance
            )

            LOGGER.info(
                "[#%r] Created light response: id=%r, issuer=%r, in_response_to=%r, "
                "citizen_country=%r, origin_country=%r, status=%s, substatus=%s.",
                self.log_id,
                self.light_response.id,
                self.light_response.issuer,
                self.light_response.in_response_to_id,
                self.auxiliary_data.get("citizen_country"),
                self.auxiliary_data.get("origin_country"),
                cast(Status, self.light_response.status).status_code,
                cast(Status, self.light_response.status).sub_status_code,
            )

            self.rewrite_name_id()

            LOGGER.debug("Light Response: %s", self.light_response)
            self.light_token, self.encoded_token = self.create_light_token(
                token_settings["issuer"],
                token_settings["hash_algorithm"],
                token_settings["secret"],
            )
            LOGGER.debug("Light Token: %s", self.light_token)
            self.storage.put_light_response(self.light_token.id, self.light_response)
        except EidasNodeError as e:
            LOGGER.exception("[#%r] Bad identity provider response: %s", self.log_id, e)
            self.error = _("Bad identity provider response.")
            return HttpResponseBadRequest(
                select_template(self.get_template_names()).render(self.get_context_data(), self.request)
            )
        return super().get(request)

    def rewrite_name_id(self):
        """Rewrite name id if needed."""
        assert self.light_response is not None
        assert self.auxiliary_data is not None
        if (
            not cast(Status, self.light_response.status).failure
            and PROXY_SERVICE_SETTINGS.transient_name_id_fallback
            and self.auxiliary_data.get("name_id_format") == NameIdFormat.TRANSIENT.value
            and self.light_response.subject_name_id_format != NameIdFormat.TRANSIENT
        ):
            random_id = str(uuid4())
            LOGGER.debug("Rewriting name id to transient id: %r → %r.", self.light_response.subject, random_id)
            self.light_response.subject_name_id_format = NameIdFormat.TRANSIENT
            self.light_response.subject = random_id

    def get_saml_response(
        self, key_source: Optional[str], key_location: Optional[str], cert_file: Optional[str]
    ) -> SAMLResponse:
        """
        Extract and decrypt a SAML response from POST data.

        :param key_source: An optional source ('file' or 'engine') to a key to decrypt the response.
        :param key_location: An optional path to a key to decrypt the response.
        :param cert_file: An optional path to a certificate to verify the response.
        :return: A SAML response.
        """
        raw_response = b64decode(self.request.POST.get("SAMLResponse", "").encode("ascii")).decode("utf-8")
        LOGGER.debug("Raw SAML Response: %s", raw_response)

        try:
            response = SAMLResponse(parse_xml(raw_response), self.request.POST.get("RelayState"))
        except XMLSyntaxError as e:
            raise ParseError(str(e)) from None

        LOGGER.info(
            "[#%r] Received SAML response: id=%r, issuer=%r, in_response_to_id=%r",
            self.log_id,
            response.id,
            response.issuer,
            response.in_response_to_id,
        )

        if cert_file:
            response.verify_response(cert_file)
        if key_source and key_location:
            response.decrypt(key_source, key_location)
        if cert_file:
            response.verify_assertion(cert_file)
        return response

    def get_light_storage(self, backend: str, options: Dict[str, Any]) -> LightStorage:
        """
        Create a light storage instance.

        :param backend: A fully qualified name of the backend class.
        :param options: The options to pass to the backend.
        :return: A light storage instance.
        """
        return import_from_module(backend)(**options)

    def create_light_response(
        self, issuer: str, auth_class_map: Optional[Dict[str, LevelOfAssurance]] = None
    ) -> LightResponse:
        """
        Create a light response from SAML response.

        :param issuer: The issuer of the light response.
        :param auth_class_map: Mapping of non-LoA auth classes to LevelOfAssurance.
        :return: A light response.
        """
        assert self.saml_response is not None
        response = self.saml_response.create_light_response(auth_class_map)
        # Use our issuer specified in the generic eIDAS Node configuration.
        response.issuer = issuer
        return response

    def create_light_token(self, issuer: str, hash_algorithm: str, secret: str) -> Tuple[LightToken, str]:
        """
        Create and encode a light token according to token settings.

        :param issuer: Token issuer.
        :param hash_algorithm: A hashlib hash algorithm.
        :param secret: A secret shared between communication parties.
        :return: A tuple of the token and its encoded form.
        """
        token = LightToken(id=create_xml_uuid(TOKEN_ID_PREFIX), created=datetime.now(), issuer=issuer)
        LOGGER.info("[#%r] Created light token: id=%r, issuer=%r", self.log_id, token.id, token.issuer)
        encoded_token = token.encode(hash_algorithm, secret).decode("ascii")
        LOGGER.info("[#%r] Encoded light token: %r", self.log_id, encoded_token)
        return token, encoded_token

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context["error"] = self.error
        if self.encoded_token:
            context["eidas_url"] = PROXY_SERVICE_SETTINGS.eidas_node["proxy_service_response_url"]
            context["token"] = self.encoded_token
            context["token_parameter"] = PROXY_SERVICE_SETTINGS.response_token["parameter_name"]
        return context
