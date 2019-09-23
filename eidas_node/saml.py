"""Conversion of SAML Requests/Responses and Light Requests/Responses."""
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Optional, Set, Type, TypeVar

from lxml import etree
from lxml.etree import Element, ElementTree, QName, SubElement

from eidas_node.attributes import ATTRIBUTE_MAP, EIDAS_ATTRIBUTE_NAME_FORMAT
from eidas_node.constants import ServiceProviderType, StatusCode, SubStatusCode
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.models import LevelOfAssurance, LightRequest, LightResponse, NameIdFormat, Status
from eidas_node.utils import datetime_iso_format_milliseconds
from eidas_node.xml import (XML_ENC_NAMESPACE, XML_SIG_NAMESPACE, decrypt_xml, dump_xml, get_element_path,
                            is_xml_id_valid, sign_xml_node, verify_xml_signatures)

EIDAS_NAMESPACES = {
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'eidas': 'http://eidas.europa.eu/saml-extensions',
}  # type: Dict[str, str]
"""XML namespaces in SAML requests/responses."""

KNOWN_NAMESPACES = {
    'xmlenc': XML_ENC_NAMESPACE,
    'ds': XML_SIG_NAMESPACE,
}
KNOWN_NAMESPACES.update(EIDAS_NAMESPACES)

KNOWN_TAGS = {
    'saml2': {'Issuer', 'AuthnContextClassRef', 'EncryptedAssertion', 'Assertion', 'Subject', 'NameID',
              'AuthnStatement', 'AttributeStatement', 'Attribute', 'AttributeValue', 'SubjectLocality',
              'AuthnContext', 'AuthnContextClassRef'},
    'saml2p': {'AuthnRequest', 'Extensions', 'NameIDPolicy', 'RequestedAuthnContext',
               'Response', 'Status', 'StatusCode', 'StatusMessage'},
    'eidas': {'SPType', 'SPCountry', 'RequestedAttributes', 'RequestedAttribute', 'AttributeValue'},
    'xmlenc': {'EncryptedData'},
    'ds': {'Signature'}
}  # type: Dict[str, Set[str]]
"""Recognized XML tags in SAML requests."""

Q_NAMES = {
    '{}:{}'.format(ns, tag): QName(KNOWN_NAMESPACES[ns], tag) for ns, tags in KNOWN_TAGS.items() for tag in tags
}  # type: Dict[str, QName]
"""Qualified names of recognized XML tags in SAML requests."""

SAMLRequestType = TypeVar('SAMLRequestType', bound='SAMLRequest')
SAMLResponseType = TypeVar('SAMLResponseType', bound='SAMLResponse')


class SAMLRequest:
    """SAML Request and its conversion from/to LightRequest."""

    document = None  # type: ElementTree
    """SAML document as an element tree."""
    citizen_country_code = None  # type: Optional[str]
    """Country code of the requesting citizen."""
    relay_state = None  # type: Optional[str]
    """Relay state associated with the request."""

    def __init__(self, document: ElementTree,
                 citizen_country_code: Optional[str] = None,
                 relay_state: Optional[str] = None):
        self.document = document
        self.citizen_country_code = citizen_country_code
        self.relay_state = relay_state

    @classmethod
    def from_light_request(cls: Type[SAMLRequestType], light_request: LightRequest,
                           destination: str, issued: datetime) -> SAMLRequestType:
        """
        Convert Light Request to SAML Request.

        :param light_request: The light request to convert.
        :param destination: A URI reference indicating the address to which this request has been sent.
        :param issued: The UTC time instant of issue of the request.
        :return: A SAML Request.
        """
        light_request.validate()
        if not is_xml_id_valid(light_request.id):
            raise ValidationError({'id': 'Light request id is not a valid XML id: {!r}'.format(light_request.id)})

        root_attributes = OrderedDict([
            ('Consent', 'urn:oasis:names:tc:SAML:2.0:consent:unspecified'),  # optional, default 'unspecified'
            ('Destination', destination),
            ('ID', light_request.id),
            ('IssueInstant', datetime_iso_format_milliseconds(issued) + 'Z'),  # UTC
            ('Version', '2.0'),
            ('IsPassive', 'false'),  # optional, default false
            ('ForceAuthn', 'true'),  # optional, default false
        ])
        if light_request.provider_name is not None:
            root_attributes['ProviderName'] = light_request.provider_name
        root = etree.Element(Q_NAMES['saml2p:AuthnRequest'], attrib=root_attributes, nsmap=EIDAS_NAMESPACES)

        # 1. RequestAbstractType <saml2:Issuer>:
        if light_request.issuer is not None:
            SubElement(root, Q_NAMES['saml2:Issuer'],
                       {'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'}).text = light_request.issuer

        # 2. RequestAbstractType <ds:Signature> skipped
        # 3. RequestAbstractType <saml2p:Extensions>:
        extensions = SubElement(root, Q_NAMES['saml2p:Extensions'])
        if light_request.sp_type:
            SubElement(extensions, Q_NAMES['eidas:SPType']).text = light_request.sp_type.value
        if light_request.origin_country_code:
            SubElement(extensions, Q_NAMES['eidas:SPCountry']).text = light_request.origin_country_code
        attributes = SubElement(extensions, Q_NAMES['eidas:RequestedAttributes'])
        for name, values in light_request.requested_attributes.items():
            attribute = SubElement(attributes, Q_NAMES['eidas:RequestedAttribute'],
                                   create_attribute_elm_attributes(name, True))
            for value in values:
                SubElement(attribute, Q_NAMES['eidas:AttributeValue']).text = value

        # 4. AuthnRequestType <saml2:Subject> skipped
        # 5. AuthnRequestType <saml2p:NameIDPolicy>:
        if light_request.name_id_format:
            SubElement(root, Q_NAMES['saml2p:NameIDPolicy'], {
                'AllowCreate': 'true',  # optional, default false
                'Format': light_request.name_id_format.value
            })
        # 6. AuthnRequestType <saml2:Conditions> skipped
        # 7. AuthnRequestType <saml2p:RequestedAuthnContext>:
        SubElement(SubElement(root, Q_NAMES['saml2p:RequestedAuthnContext'], {'Comparison': 'minimum'}),
                   Q_NAMES['saml2:AuthnContextClassRef']).text = light_request.level_of_assurance.value
        # 8: AuthnRequestType <saml2p:Scoping> skipped
        return cls(ElementTree(root), light_request.citizen_country_code, light_request.relay_state)

    @property
    def request_signature(self) -> Optional[Element]:
        """Get an element of the XML signature of the whole SAML request."""
        return self.document.getroot().find('./{}'.format(Q_NAMES['ds:Signature']))

    def create_light_request(self) -> LightRequest:
        """
        Convert SAML Request to Light Request.

        :return: A Light Request.
        :raise ValidationError: If the SAML Request cannot be parsed correctly.
        """
        request = LightRequest(requested_attributes=OrderedDict(),
                               citizen_country_code=self.citizen_country_code,
                               relay_state=self.relay_state)
        root = self.document.getroot()
        if root.tag != Q_NAMES['saml2p:AuthnRequest']:
            raise ValidationError({get_element_path(root): 'Wrong root element: {!r}'.format(root.tag)})

        request.id = root.attrib.get('ID')
        request.provider_name = root.attrib.get('ProviderName')

        issuer = root.find('./{}'.format(Q_NAMES['saml2:Issuer']))
        if issuer is not None:
            request.issuer = issuer.text

        name_id_format = root.find('./{}'.format(Q_NAMES['saml2p:NameIDPolicy']))
        if name_id_format is not None:
            request.name_id_format = NameIdFormat(name_id_format.attrib.get('Format'))

        level_of_assurance = root.find(
            './{}/{}'.format(Q_NAMES['saml2p:RequestedAuthnContext'], Q_NAMES['saml2:AuthnContextClassRef']))
        if level_of_assurance is not None:
            request.level_of_assurance = LevelOfAssurance(level_of_assurance.text)

        extensions = root.find('./{}'.format(Q_NAMES['saml2p:Extensions']))
        if extensions is not None:
            sp_type = extensions.find('./{}'.format(Q_NAMES['eidas:SPType']))
            if sp_type is not None:
                request.sp_type = ServiceProviderType(sp_type.text)

            sp_country = extensions.find('./{}'.format(Q_NAMES['eidas:SPCountry']))
            if sp_country is not None:
                request.origin_country_code = sp_country.text

            requested_attributes = request.requested_attributes
            attributes = extensions.findall(
                './{}/{}'.format(Q_NAMES['eidas:RequestedAttributes'], Q_NAMES['eidas:RequestedAttribute']))
            for attribute in attributes:
                name = attribute.attrib.get('Name')
                if not name:
                    raise ValidationError({
                        get_element_path(attribute): "Missing attribute 'Name'"})
                values = requested_attributes[name] = []
                for value in attribute.findall('./{}'.format(Q_NAMES['eidas:AttributeValue'])):
                    values.append(value.text)

        return request

    def sign_request(self, key_file: str, cert_file: str, signature_method: str, digest_method: str) -> None:
        """
        Sign the whole SAML request.

        :raise SecurityError: If the signature already exists.
        """
        if self.request_signature is not None:
            raise SecurityError('Request signature already exists.')

        sign_xml_node(self.document.getroot(), key_file, cert_file, signature_method, digest_method)

    def verify_request(self, cert_file: str) -> None:
        """Verify XML signature of the whole request."""
        signature = self.request_signature
        if signature is None:
            raise SecurityError('Signature does not exist.')

        # We need to check not only that a valid signature exists but it must also reference the correct element.
        for valid_signature, references in verify_xml_signatures(self.document.getroot(), cert_file):
            if valid_signature is signature:
                if signature.getparent() not in references:
                    raise SecurityError('Signature does not reference parent element.')
                break
        else:
            raise SecurityError('Signature not found.')

    def __str__(self) -> str:
        return 'citizen_country_code = {!r}, relay_state = {!r}, document = {}'.format(
            self.citizen_country_code,
            self.relay_state,
            dump_xml(self.document).decode('utf-8') if self.document else 'None')


class SAMLResponse:
    """
    SAML Response and its conversion from/to LightResponse.

    :param document: A SAML response as XML document.
    :param relay_state: Optional relay state to return to the requesting party.
    """

    document = None  # type: ElementTree
    relay_state = None  # type: Optional[str]

    def __init__(self, document: ElementTree, relay_state: Optional[str] = None):
        self.document = document
        self.relay_state = relay_state

    @property
    def assertion(self) -> Optional[Element]:
        """Get SAML assertion element."""
        root = self.document.getroot()
        candidate1 = root.find('./{}'.format(Q_NAMES['saml2:Assertion']))
        candidate2 = root.find('./{}/{}'.format(Q_NAMES['saml2:EncryptedAssertion'], Q_NAMES['saml2:Assertion']))
        if candidate1 is not None and candidate2 is not None:
            raise ParseError('Too many assertion elements.')
        return candidate2 if candidate1 is None else candidate1

    @property
    def response_signature(self) -> Optional[Element]:
        """Get an element of the XML signature of the whole SAML response."""
        return self.document.getroot().find('./{}'.format(Q_NAMES['ds:Signature']))

    @property
    def assertion_signature(self) -> Optional[Element]:
        """Get an element of XML signature of SAML assertion."""
        assertion = self.assertion
        return assertion.find('./{}'.format(Q_NAMES['ds:Signature'])) if assertion is not None else None

    @classmethod
    def from_light_response(cls: Type[SAMLResponseType],
                            light_response: LightResponse,
                            destination: Optional[str],
                            issued: datetime) -> SAMLResponseType:
        """Convert light response to SAML response."""
        light_response.validate()
        issue_instant = datetime_iso_format_milliseconds(issued) + 'Z'  # UTC
        root_attributes = {
            'ID': light_response.id,
            'InResponseTo': light_response.in_response_to_id,
            'Version': '2.0',
            'IssueInstant': issue_instant,
        }
        if destination is not None:
            root_attributes['Destination'] = destination
        root = etree.Element(Q_NAMES['saml2p:Response'], attrib=root_attributes, nsmap=EIDAS_NAMESPACES)
        # 1. StatusResponseType <saml2:Issuer> optional
        if light_response.issuer is not None:
            SubElement(root, Q_NAMES['saml2:Issuer']).text = light_response.issuer
        # 2. StatusResponseType <ds:Signature> optional, skipped
        # 3. StatusResponseType <saml2p:Extensions> optional, skipped
        # 4. StatusResponseType <saml2p:Status> required
        status = light_response.status
        assert status is not None
        status_elm = SubElement(root, Q_NAMES['saml2p:Status'])
        # 4.1 <saml2p:Status> <saml2p:StatusCode> required
        status_code = status.status_code
        sub_status_code = status.sub_status_code
        if status_code is None:
            status_code = StatusCode.SUCCESS if not status.failure else StatusCode.RESPONDER

        # VERSION_MISMATCH is a status code in SAML 2 but a sub status code in Light response!
        if sub_status_code == SubStatusCode.VERSION_MISMATCH:
            status_code_value = SubStatusCode.VERSION_MISMATCH.value
            sub_status_code_value = None
        else:
            status_code_value = status_code.value
            sub_status_code_value = None if sub_status_code is None else sub_status_code.value

        status_code_elm = SubElement(status_elm, Q_NAMES['saml2p:StatusCode'], {'Value': status_code_value})
        if sub_status_code_value is not None:
            SubElement(status_code_elm, Q_NAMES['saml2p:StatusCode'], {'Value': sub_status_code_value})
        # 4.2 <saml2p:Status> <saml2p:StatusMessage> optional
        if status.status_message is not None:
            SubElement(status_elm, Q_NAMES['saml2p:StatusMessage']).text = status.status_message
        # 4.3 <saml2p:Status> <saml2p:StatusDetail> optional, skipped
        if not status.failure:
            # 5. AssertionType
            assertion_elm = SubElement(root, Q_NAMES['saml2:Assertion'], {
                'ID': '_' + light_response.id,
                'Version': '2.0',
                'IssueInstant': issue_instant,
            })
            # 5.1 AssertionType <saml2:Issuer> required
            SubElement(assertion_elm, Q_NAMES['saml2:Issuer']).text = light_response.issuer
            # 5.2 AssertionType <ds:Signature> optional, skipped
            # 5.3 AssertionType <saml2:Subject> optional
            SubElement(SubElement(assertion_elm, Q_NAMES['saml2:Subject']), Q_NAMES['saml2:NameID'],
                       {'Format': light_response.subject_name_id_format.value}).text = light_response.subject
            # 5.4 AssertionType <saml2:Conditions> optional, skipped
            # 5.5 AssertionType <saml2:Advice> optional, skipped
            # 5.5 AssertionType <saml2:Advice> optional, skipped
            # 5.6 AssertionType <saml2:AttributeStatement>
            attributes_elm = SubElement(assertion_elm, Q_NAMES['saml2:AttributeStatement'])
            for name, values in light_response.attributes.items():
                attribute = SubElement(attributes_elm, Q_NAMES['saml2:Attribute'],
                                       create_attribute_elm_attributes(name, None))
                for value in values:
                    SubElement(attribute, Q_NAMES['saml2:AttributeValue']).text = value

            # 5.7 AssertionType <saml2:AuthnStatement>
            statement_elm = SubElement(assertion_elm, Q_NAMES['saml2:AuthnStatement'], {'AuthnInstant': issue_instant})
            if light_response.ip_address is not None:
                SubElement(statement_elm, Q_NAMES['saml2:SubjectLocality'], {'Address': light_response.ip_address})
            SubElement(SubElement(statement_elm, Q_NAMES['saml2:AuthnContext']),
                       Q_NAMES['saml2:AuthnContextClassRef']).text = light_response.level_of_assurance.value

        return cls(ElementTree(root), light_response.relay_state)

    def decrypt(self, key_file: str) -> None:
        """Decrypt encrypted SAML response."""
        decrypt_xml(self.document, key_file)

    def sign_assertion(self, key_file: str, cert_file: str, signature_method: str, digest_method: str) -> bool:
        """
        Sign the SAML assertion.

        :return: `True` if the assertion element is present and has been signed, `False` otherwise.
        :raise SecurityError: If the assertion or response signature is already present.
        """
        assertion = self.document.getroot().find('./{}'.format(Q_NAMES['saml2:Assertion']))
        if assertion is None:
            # Failure responses don't contain <Assertion>.
            return False

        if self.assertion_signature is not None:
            raise SecurityError('The assertion signature is already present.')

        if self.response_signature is not None:
            # Signing assertion would invalidate the response signature.
            raise SecurityError('Cannot sign assertion because response signature is already present.')

        sign_xml_node(assertion, key_file, cert_file, signature_method, digest_method)
        return True

    def sign_response(self, key_file: str, cert_file: str, signature_method: str, digest_method: str) -> None:
        """
        Sign the whole SAML response.

        :raise SecurityError: If the response signature is already present.
        """
        if self.response_signature is not None:
            raise SecurityError('The response signature is already present.')

        sign_xml_node(self.document.getroot(), key_file, cert_file, signature_method, digest_method)

    def _verify_and_remove_signature(self, signature: Optional[Element], cert_file: str) -> None:
        """Verify signature and remove it from document."""
        if signature is None:
            raise SecurityError('Signature does not exist.')

        # We need to check not only that a valid signature exists but it must also reference the correct element.
        for valid_signature, references in verify_xml_signatures(self.document.getroot(), cert_file):
            if valid_signature is signature:
                if signature.getparent() not in references:
                    raise SecurityError('Signature does not reference parent element.')

                # Remove the signature as further document manipulations might invalidate it.
                # E.g., decrypting an encrypted assertion invalidates signature of the whole response.
                signature.getparent().remove(signature)
                break
        else:
            raise SecurityError('Signature not found.')

    def verify_response(self, cert_file: str) -> None:
        """Verify XML signature of the whole response."""
        self._verify_and_remove_signature(self.response_signature, cert_file)

    def verify_assertion(self, cert_file: str) -> bool:
        """Verify XML signature of the assertion."""
        if self.assertion is None:
            return False
        self._verify_and_remove_signature(self.assertion_signature, cert_file)
        return True

    def create_light_response(self) -> LightResponse:
        """Convert SAML response to light response."""
        response = LightResponse(attributes=OrderedDict())
        root = self.document.getroot()
        if root.tag != Q_NAMES['saml2p:Response']:
            raise ValidationError({
                get_element_path(root): 'Wrong root element: {!r}'.format(root.tag)})

        response.id = root.get('ID')
        response.in_response_to_id = root.get('InResponseTo')
        issuer_elm = root.find('./{}'.format(Q_NAMES['saml2:Issuer']))
        if issuer_elm is not None:
            response.issuer = issuer_elm.text

        response.status = status = Status()
        status_code_elm = root.find('./{}/{}'.format(Q_NAMES['saml2p:Status'], Q_NAMES['saml2p:StatusCode']))
        if status_code_elm is not None:
            sub_status_code_elm = status_code_elm.find('./{}'.format(Q_NAMES['saml2p:StatusCode']))
            status_message_elm = root.find('./{}/{}'.format(Q_NAMES['saml2p:Status'], Q_NAMES['saml2p:StatusMessage']))

            status_code = status_code_elm.get('Value')
            sub_status_code = sub_status_code_elm.get('Value') if sub_status_code_elm is not None else None

            if status_code == SubStatusCode.VERSION_MISMATCH.value:
                # VERSION_MISMATCH is a status code in SAML 2 but a sub status code in Light response!
                status.status_code = StatusCode.REQUESTER
                status.sub_status_code = SubStatusCode.VERSION_MISMATCH
            else:
                status.status_code = StatusCode(status_code)
                try:
                    status.sub_status_code = SubStatusCode(sub_status_code)
                except ValueError:
                    # None or a sub status codes not recognized by eIDAS
                    status.sub_status_code = None

            status.failure = status.status_code != StatusCode.SUCCESS
            if status_message_elm is not None:
                status.status_message = status_message_elm.text

        assertion_elm = self.assertion
        if assertion_elm is not None:
            try:
                self._parse_assertion(response, assertion_elm)
            except ValidationError as e:
                return LightResponse(
                    id=root.get('ID'),
                    in_response_to_id=root.get('InResponseTo'),
                    issuer=issuer_elm.text if issuer_elm is not None else None,
                    status=Status(
                        failure=True,
                        status_code=StatusCode.RESPONDER,
                        status_message='Invalid data of {!r}: {!r}'.format(*e.errors.popitem())))

        response.relay_state = self.relay_state
        return response

    def _parse_assertion(self, response: LightResponse, assertion: Element) -> None:
        attributes = response.attributes = OrderedDict()
        name_id_elm = assertion.find('./{}/{}'.format(Q_NAMES['saml2:Subject'], Q_NAMES['saml2:NameID']))
        if name_id_elm is not None:
            response.subject = name_id_elm.text
            response.subject_name_id_format = NameIdFormat(name_id_elm.get('Format'))

        attribute_elms = assertion.findall('./{}/{}'.format(Q_NAMES['saml2:AttributeStatement'],
                                                            Q_NAMES['saml2:Attribute']))
        for attribute in attribute_elms:
            attributes[attribute.get('Name')] = [
                elm.text for elm in attribute.findall('./{}'.format(Q_NAMES['saml2:AttributeValue']))]

        stm_elm = assertion.find('./{}'.format(Q_NAMES['saml2:AuthnStatement']))
        if stm_elm is not None:
            locality_elm = stm_elm.find('./{}'.format(Q_NAMES['saml2:SubjectLocality']))
            if locality_elm is not None:
                response.ip_address = locality_elm.get('Address')

            authn_class_elm = stm_elm.find('./{}/{}'.format(Q_NAMES['saml2:AuthnContext'],
                                                            Q_NAMES['saml2:AuthnContextClassRef']))
            if authn_class_elm is not None:
                try:
                    response.level_of_assurance = LevelOfAssurance(authn_class_elm.text)
                except ValueError:
                    raise ValidationError({get_element_path(authn_class_elm): authn_class_elm.text}) from None

    def __str__(self) -> str:
        return 'relay_state = {!r}, document = {}'.format(
            self.relay_state, dump_xml(self.document).decode('utf-8') if self.document else 'None')


def create_attribute_elm_attributes(name: str, required: Optional[bool]) -> Element:
    """Create attributes for an attribute element."""
    attribute = ATTRIBUTE_MAP.get(name)
    attributes = {
        'Name': name,
        'FriendlyName': attribute.friendly_name if attribute else name.rsplit('/', 1)[-1],
        'NameFormat': attribute.name_format if attribute else EIDAS_ATTRIBUTE_NAME_FORMAT,
    }
    if required is not None:
        attributes['isRequired'] = 'true' if required else 'false'
    return attributes
