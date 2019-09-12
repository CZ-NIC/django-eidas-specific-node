"""Views of eidas_node.connector."""
import hmac
import logging
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.template.loader import select_template
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from lxml.etree import XMLSyntaxError

from eidas_node.attributes import MANDATORY_ATTRIBUTE_NAMES
from eidas_node.connector.settings import CONNECTOR_SETTINGS
from eidas_node.constants import TOKEN_ID_PREFIX
from eidas_node.errors import EidasNodeError, ParseError, SecurityError
from eidas_node.models import LightRequest, LightResponse, LightToken
from eidas_node.saml import SAMLRequest, SAMLResponse
from eidas_node.storage import LightStorage
from eidas_node.utils import create_xml_uuid, dump_xml, import_from_module, parse_xml

LOGGER = logging.getLogger('eidas_node.connector')


class ServiceProviderRequestView(TemplateView):
    """
    Forward a service provider's request to an identity provider.

    eIDAS Generic Connector expect the service provider's request as a light request.
    """

    http_method_names = ['post']
    template_name = 'eidas_node/connector/service_provider_request.html'
    error = None  # type: Optional[str]
    storage = None  # type: LightStorage
    saml_request = None  # type: SAMLRequest
    light_request = None  # type: LightRequest
    light_token = None  # type: LightToken
    encoded_token = None  # type: str

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        try:
            self.saml_request = self.get_saml_request(CONNECTOR_SETTINGS.service_provider['country_parameter'])
            LOGGER.debug('SAML Request: %s', self.saml_request)
            self.light_request = self.create_light_request(CONNECTOR_SETTINGS.service_provider['request_issuer'],
                                                           CONNECTOR_SETTINGS.eidas_node['request_issuer'])
            self.adjust_requested_attributes(self.light_request.requested_attributes)
            LOGGER.debug('Light Request: %s', self.light_request)

            token_settings = CONNECTOR_SETTINGS.request_token
            self.light_token, self.encoded_token = self.create_light_token(
                token_settings['issuer'],
                token_settings['hash_algorithm'],
                token_settings['secret'], )
            LOGGER.debug('Light Token: %s', self.light_token)

            self.storage = self.get_light_storage(CONNECTOR_SETTINGS.light_storage['backend'],
                                                  CONNECTOR_SETTINGS.light_storage['options'])
            self.storage.put_light_request(self.light_token.id, self.light_request)
        except (EidasNodeError, MultiValueDictKeyError):
            LOGGER.exception('Bad service provider request.')
            self.error = _('Bad service provider request.')
            return HttpResponseBadRequest(
                select_template(self.get_template_names()).render(self.get_context_data(), self.request))
        return super().get(request)

    def get_saml_request(self, country_parameter: str) -> SAMLRequest:
        """
        Extract and decrypt a SAML request from POST data.

        :param country_parameter: A parameter containing citizen country code.
        :return: A SAML request.
        """
        try:
            request = SAMLRequest(
                parse_xml(b64decode(self.request.POST.get('SAMLRequest', '').encode('ascii'))),
                self.request.POST[country_parameter].upper(),
                self.request.POST.get('RelayState'))
        except XMLSyntaxError as e:
            raise ParseError(str(e)) from None
        # TODO: Verify signature.
        # TODO: Decrypt encrypted request.
        return request

    def create_light_request(self, saml_issuer: str, light_issuer: str) -> LightRequest:
        """
        Create a light request from a SAML request.

        :param saml_issuer: The expected issuer of the SAML request.
        :param light_issuer: The issuer of the light request.
        :return: A light request.
        """
        request = self.saml_request.create_light_request()
        # Verify the original issuer of the request.
        if not request.issuer or not hmac.compare_digest(request.issuer, saml_issuer):
            raise SecurityError('Invalid SAML request issuer: {!r}'.format(request.issuer))
        # Use our issuer specified in the generic eIDAS Node configuration.
        request.issuer = light_issuer
        return request

    def adjust_requested_attributes(self, attributes: Dict[str, List[str]]) -> None:
        """Adjust requested attributes of the incoming authorization request."""
        for missing in MANDATORY_ATTRIBUTE_NAMES - set(attributes):
            attributes[missing] = []

    def create_light_token(self, issuer: str, hash_algorithm: str, secret: str) -> Tuple[LightToken, str]:
        """
        Create and encode a light token according to token settings.

        :param issuer: Token issuer.
        :param hash_algorithm: A hashlib hash algorithm.
        :param secret: A secret shared between communication parties.
        :return: A tuple of the token and its encoded form.
        """
        token = LightToken(id=create_xml_uuid(TOKEN_ID_PREFIX), created=datetime.utcnow(), issuer=issuer)
        encoded_token = token.encode(hash_algorithm, secret).decode('ascii')
        return token, encoded_token

    def get_light_storage(self, backend: str, options: Dict[str, Any]) -> LightStorage:
        """
        Create a light storage instance.

        :param backend: A fully qualified name of the backend class.
        :param options: The options to pass to the backend.
        :return: A light storage instance.
        """
        return import_from_module(backend)(**options)

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context['error'] = self.error
        if self.encoded_token:
            context['eidas_url'] = CONNECTOR_SETTINGS.eidas_node['connector_request_url']
            context['token'] = self.encoded_token
            context['token_parameter'] = CONNECTOR_SETTINGS.request_token['parameter_name']
        return context


class ConnectorResponseView(TemplateView):
    """
    Forward identity provider's response to a service provider.

    eIDAS Generic Connector provides the identity provider's response as a light response.
    """

    http_method_names = ['post']
    template_name = 'eidas_node/connector/connector_response.html'
    error = None  # type: Optional[str]
    storage = None  # type: LightStorage
    light_token = None  # type: LightToken
    light_response = None  # type: LightResponse
    saml_response = None  # type: SAMLResponse

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        try:
            token_settings = CONNECTOR_SETTINGS.response_token
            self.light_token = self.get_light_token(
                token_settings['parameter_name'],
                token_settings['issuer'],
                token_settings['hash_algorithm'],
                token_settings['secret'],
                token_settings['lifetime'])
            LOGGER.debug('Light Token: %s', self.light_token)
            self.storage = self.get_light_storage(CONNECTOR_SETTINGS.light_storage['backend'],
                                                  CONNECTOR_SETTINGS.light_storage['options'])
            self.light_response = self.get_light_response()
            LOGGER.debug('Light Response: %s', self.light_response)
            self.saml_response = self.create_saml_response(CONNECTOR_SETTINGS.service_provider['response_issuer'],
                                                           CONNECTOR_SETTINGS.service_provider['endpoint'])
            LOGGER.debug('SAML Response: %s', self.saml_response)
        except EidasNodeError:
            LOGGER.exception('Bad connector response.')
            self.error = _('Bad connector response.')
            return HttpResponseBadRequest(
                select_template(self.get_template_names()).render(self.get_context_data(), self.request))
        return super().get(request)

    def get_light_token(self, parameter_name: str, issuer: str, hash_algorithm: str,
                        secret: str, lifetime: Optional[int] = None) -> LightToken:
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
        encoded_token = self.request.POST.get(parameter_name, '').encode('utf-8')
        token = LightToken.decode(encoded_token, hash_algorithm, secret)
        if token.issuer != issuer:
            raise SecurityError('Invalid token issuer: {!r}.'.format(token.issuer))
        if lifetime and token.created + timedelta(minutes=lifetime) < datetime.now():
            raise SecurityError('Token has expired.')
        return token

    def get_light_storage(self, backend: str, options: Dict[str, Any]) -> LightStorage:
        """
        Create a light storage instance.

        :param backend: A fully qualified name of the backend class.
        :param options: The options to pass to the backend.
        :return: A light storage instance.
        """
        return import_from_module(backend)(**options)

    def get_light_response(self) -> LightResponse:
        """
        Get a light response.

        :return: A light response.
        :raise SecurityError: If the response is not found.
        """
        response = self.storage.get_light_response(self.light_token.id)
        if response is None:
            raise SecurityError('Response not found in light storage.')
        return response

    def create_saml_response(self, issuer: str, destination: Optional[str]) -> SAMLResponse:
        """
        Create a SAML response from a light response.

        :param issuer: Issuer of the SAML response.
        :param destination: Service provider's endpoint.
        :return: A SAML response.
        """
        # Replace the original issuer with our issuer registered at the Identity Provider.
        self.light_response.issuer = issuer
        response = SAMLResponse.from_light_response(
            self.light_response,
            destination,
            datetime.utcnow())
        # TODO: sign and encrypt the response
        return response

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context['error'] = self.error

        if self.saml_response:
            context['service_provider_endpoint'] = CONNECTOR_SETTINGS.service_provider['endpoint']
            context['saml_response'] = b64encode(dump_xml(self.saml_response.document)).decode('ascii')
            context['relay_state'] = self.saml_response.relay_state or ''
        return context
