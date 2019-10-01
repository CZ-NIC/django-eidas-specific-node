"""Views of eidas_node.proxy_service."""
import logging
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.template.loader import select_template
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from lxml.etree import XMLSyntaxError

from eidas_node.constants import TOKEN_ID_PREFIX
from eidas_node.errors import EidasNodeError, ParseError, SecurityError
from eidas_node.models import LightRequest, LightResponse, LightToken
from eidas_node.proxy_service.settings import PROXY_SERVICE_SETTINGS
from eidas_node.saml import SAMLRequest, SAMLResponse
from eidas_node.storage import LightStorage
from eidas_node.utils import import_from_module
from eidas_node.xml import create_xml_uuid, dump_xml, parse_xml

LOGGER = logging.getLogger('eidas_node.proxy_service')


class ProxyServiceRequestView(TemplateView):
    """
    Forward service provider's request to an identity provider.

    eIDAS Generic Proxy Service provides the service provider's request as a light request.
    """

    http_method_names = ['post']
    template_name = 'eidas_node/proxy_service/proxy_service_request.html'
    error = None  # type: Optional[str]
    storage = None  # type: LightStorage
    light_token = None  # type: LightToken
    light_request = None  # type: LightRequest
    saml_request = None  # type: SAMLRequest

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        try:
            token_settings = PROXY_SERVICE_SETTINGS.request_token
            self.light_token = self.get_light_token(
                token_settings['parameter_name'],
                token_settings['issuer'],
                token_settings['hash_algorithm'],
                token_settings['secret'],
                token_settings['lifetime'])
            LOGGER.debug('Light Token: %s', self.light_token)
            self.storage = self.get_light_storage(PROXY_SERVICE_SETTINGS.light_storage['backend'],
                                                  PROXY_SERVICE_SETTINGS.light_storage['options'])
            self.light_request = self.get_light_request()
            LOGGER.debug('Light Request: %s', self.light_request)
            self.saml_request = self.create_saml_request(PROXY_SERVICE_SETTINGS.identity_provider['request_issuer'],
                                                         PROXY_SERVICE_SETTINGS.identity_provider['request_signature'])
            LOGGER.debug('SAML Request: %s', self.saml_request)
        except EidasNodeError:
            LOGGER.exception('Bad proxy service request.')
            self.error = _('Bad proxy service request.')
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
            raise SecurityError('Invalid token issuer.')
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

    def get_light_request(self) -> LightRequest:
        """
        Get a light request.

        :return: A light request.
        :raise SecurityError: If the request is not found.
        """
        request = self.storage.pop_light_request(self.light_token.id)
        if request is None:
            raise SecurityError('Request not found in light storage.')
        return request

    def create_saml_request(self, issuer: str, signature_options: Optional[Dict[str, str]]) -> SAMLRequest:
        """
        Create a SAML request from a light request.

        :param issuer: Issuer of the SAML request.
        :param signature_options: Optional options to create a signed request: `key_file`, `cert_file`.
        `signature_method`, abd `digest_method`.
        :return: A SAML request.
        """
        # Replace the original issuer with our issuer registered at the Identity Provider.
        self.light_request.issuer = issuer

        destination = self.request.build_absolute_uri(reverse('identity-provider-response'))
        saml_request = SAMLRequest.from_light_request(self.light_request, destination, datetime.utcnow())
        if signature_options and signature_options.get('key_file') and signature_options.get('cert_file'):
            saml_request.sign_request(**signature_options)
        return saml_request

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context['error'] = self.error

        if self.saml_request:
            encoded_saml_request = b64encode(dump_xml(self.saml_request.document, pretty_print=False)).decode('ascii')
            context['identity_provider_endpoint'] = PROXY_SERVICE_SETTINGS.identity_provider['endpoint']
            context['saml_request'] = encoded_saml_request
            context['relay_state'] = self.saml_request.relay_state or ''
        return context


class IdentityProviderResponseView(TemplateView):
    """
    Forward an identity provider's response to a service provider.

    eIDAS Generic Proxy Service expect the identity provider's response as a light response.
    """

    http_method_names = ['post']
    template_name = 'eidas_node/proxy_service/identity_provider_response.html'
    error = None  # type: Optional[str]
    storage = None  # type: LightStorage
    saml_response = None  # type: SAMLResponse
    light_response = None  # type: LightResponse
    light_token = None  # type: LightToken
    encoded_token = None  # type: str

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle a HTTP POST request."""
        try:
            self.saml_response = self.get_saml_response(PROXY_SERVICE_SETTINGS.identity_provider.get('key_file'),
                                                        PROXY_SERVICE_SETTINGS.identity_provider.get('cert_file'))
            LOGGER.debug('SAML Response: %s', self.saml_response)
            self.storage = self.get_light_storage(PROXY_SERVICE_SETTINGS.light_storage['backend'],
                                                  PROXY_SERVICE_SETTINGS.light_storage['options'])
            token_settings = PROXY_SERVICE_SETTINGS.response_token
            self.light_response = self.create_light_response(
                PROXY_SERVICE_SETTINGS.eidas_node['response_issuer'])
            LOGGER.debug('Light Response: %s', self.light_response)
            self.light_token, self.encoded_token = self.create_light_token(
                token_settings['issuer'],
                token_settings['hash_algorithm'],
                token_settings['secret'], )
            LOGGER.debug('Light Token: %s', self.light_token)
            self.storage.put_light_response(self.light_token.id, self.light_response)
        except EidasNodeError:
            LOGGER.exception('Bad proxy service request.')
            self.error = _('Bad proxy service request.')
            return HttpResponseBadRequest(
                select_template(self.get_template_names()).render(self.get_context_data(), self.request))
        return super().get(request)

    def get_saml_response(self, key_file: Optional[str], cert_file: Optional[str]) -> SAMLResponse:
        """
        Extract and decrypt a SAML response from POST data.

        :param key_file: An optional path to a key to decrypt the response.
        :param cert_file: An optional path to a certificate to verify the response.
        :return: A SAML response.
        """
        raw_response = b64decode(self.request.POST.get('SAMLResponse', '').encode('ascii')).decode('utf-8')
        LOGGER.debug('Raw SAML Response: %s', raw_response)

        try:
            response = SAMLResponse(
                parse_xml(raw_response),
                self.request.POST.get('RelayState'))
        except XMLSyntaxError as e:
            raise ParseError(str(e)) from None

        if cert_file:
            response.verify_response(cert_file)
        if key_file:
            response.decrypt(key_file)
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

    def create_light_response(self, issuer: str) -> LightResponse:
        """
        Create a light response from SAML response.

        :param issuer: The issuer of the light response.
        :return: A light response.
        """
        response = self.saml_response.create_light_response()
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
        token = LightToken(id=create_xml_uuid(TOKEN_ID_PREFIX), created=datetime.utcnow(), issuer=issuer)
        encoded_token = token.encode(hash_algorithm, secret).decode('ascii')
        return token, encoded_token

    def get_context_data(self, **kwargs) -> dict:
        """Adjust template context data."""
        context = super().get_context_data(**kwargs)
        context['error'] = self.error
        if self.encoded_token:
            context['eidas_url'] = PROXY_SERVICE_SETTINGS.eidas_node['proxy_service_response_url']
            context['token'] = self.encoded_token
            context['token_parameter'] = PROXY_SERVICE_SETTINGS.response_token['parameter_name']
        return context
