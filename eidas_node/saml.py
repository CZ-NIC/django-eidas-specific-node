"""Conversion of SAML Requests/Responses and Light Requests/Responses."""
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Optional, Set, Type, TypeVar

import xmlsec
from lxml import etree
from lxml.etree import Element, ElementTree, QName, SubElement

from eidas_node.attributes import ATTRIBUTE_MAP, EIDAS_ATTRIBUTE_NAME_FORMAT
from eidas_node.constants import StatusCode, SubStatusCode
from eidas_node.errors import ValidationError
from eidas_node.models import LevelOfAssurance, LightRequest, LightResponse, NameIdFormat, Status
from eidas_node.utils import datetime_iso_format_milliseconds, dump_xml, get_element_path, is_xml_id_valid

NAMESPACES = {
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'eidas': 'http://eidas.europa.eu/saml-extensions',
    'xmlenc': 'http://www.w3.org/2001/04/xmlenc#',
}  # type: Dict[str, str]
"""XML namespaces in SAML requests."""

KNOWN_TAGS = {
    'saml2': {'Issuer', 'AuthnContextClassRef', 'EncryptedAssertion', 'Assertion', 'Subject', 'NameID',
              'AuthnStatement', 'AttributeStatement', 'Attribute', 'AttributeValue', 'SubjectLocality',
              'AuthnContext', 'AuthnContextClassRef'},
    'saml2p': {'AuthnRequest', 'Extensions', 'NameIDPolicy', 'RequestedAuthnContext',
               'Response', 'Status', 'StatusCode', 'StatusMessage'},
    'eidas': {'SPType', 'SPCountry', 'RequestedAttributes', 'RequestedAttribute', 'AttributeValue'},
    'xmlenc': {'EncryptedData'}
}  # type: Dict[str, Set[str]]
"""Recognized XML tags in SAML requests."""

Q_NAMES = {
    '{}:{}'.format(ns, tag): QName(NAMESPACES[ns], tag) for ns, tags in KNOWN_TAGS.items() for tag in tags
}  # type: Dict[str, QName]
"""Qualified names of recognized XML tags in SAML requests."""

SAMLRequestType = TypeVar('SAMLRequestType', bound='SAMLRequest')
SAMLResponseType = TypeVar('SAMLResponseType', bound='SAMLResponse')


class SAMLRequest:
    """SAML Request and its conversion from/to LightRequest."""

    document = None  # type: ElementTree
    """SAML document as an element tree."""
    relay_state = None  # type: Optional[str]
    """Relay state associated with the request."""

    def __init__(self, document: ElementTree, relay_state: Optional[str] = None):
        self.document = document
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
        root = etree.Element(Q_NAMES['saml2p:AuthnRequest'], attrib=root_attributes, nsmap=NAMESPACES)

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
            attribute = create_eidas_attribute(attributes, name, True)
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
        return cls(ElementTree(root), light_request.relay_state)

    def __str__(self) -> str:
        return 'relay_state = {!r}, document = {}'.format(
            self.relay_state, dump_xml(self.document).decode('utf-8') if self.document else 'None')


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

    def create_light_response(self) -> LightResponse:
        """Convert SAML response to light response."""
        response = LightResponse(attributes=OrderedDict())
        root = self.document.getroot()
        if root.tag != Q_NAMES['saml2p:Response']:
            raise ValidationError({
                get_element_path(root): 'Wrong root element: {!r}'.format(root.tag)})

        response.id = root.get('ID')
        response.in_response_to_id = root.get('InResponseTo')
        for elm in root:
            if elm.tag == Q_NAMES['saml2:Issuer']:
                response.issuer = elm.text
            elif elm.tag == Q_NAMES['saml2p:Status']:
                response.status = status = Status()
                for elm2 in elm:
                    if elm2.tag == Q_NAMES['saml2p:StatusCode']:
                        status_code = elm2.get('Value')
                        sub_status_code = None
                        for elm3 in elm2:
                            if elm3.tag == Q_NAMES['saml2p:StatusCode']:
                                sub_status_code = elm3.get('Value')
                                break

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
                    elif elm2.tag == Q_NAMES['saml2p:StatusMessage']:
                        status.status_message = elm2.text
            elif elm.tag == Q_NAMES['saml2:EncryptedAssertion']:
                if not len(elm):
                    raise ValidationError({get_element_path(elm): 'Missing assertion element.'})
                assertion = elm[0]
                if assertion.tag != Q_NAMES['saml2:Assertion']:
                    raise ValidationError({
                        get_element_path(assertion): 'Unexpected element: {!r}.'.format(assertion.tag)})
                self._parse_assertion(response, assertion)
            elif elm.tag == Q_NAMES['saml2:Assertion']:
                self._parse_assertion(response, elm)
        response.relay_state = self.relay_state
        return response

    def _parse_assertion(self, response: LightResponse, assertion: Element) -> None:
        attributes = response.attributes = OrderedDict()
        for elm in assertion:
            if elm.tag == Q_NAMES['saml2:Subject']:
                name_id = elm.find(Q_NAMES['saml2:NameID'])
                response.subject = name_id.text
                response.subject_name_id_format = NameIdFormat(name_id.get('Format'))
            elif elm.tag == Q_NAMES['saml2:AttributeStatement']:
                for attribute in elm:
                    if attribute.tag != Q_NAMES['saml2:Attribute']:
                        raise ValidationError({
                            get_element_path(attribute): 'Unexpected element: {!r}.'.format(attribute.tag)})
                    name = attribute.get('Name')
                    values = attributes[name] = []
                    for value in attribute:
                        if value.tag != Q_NAMES['saml2:AttributeValue']:
                            raise ValidationError({
                                get_element_path(value): 'Unexpected element: {!r}.'.format(value.tag)})
                        values.append(value.text)
            elif elm.tag == Q_NAMES['saml2:AuthnStatement']:
                for stm in elm:
                    if stm.tag == Q_NAMES['saml2:SubjectLocality']:
                        response.ip_address = stm.get('Address')
                    elif stm.tag == Q_NAMES['saml2:AuthnContext']:
                        for elm2 in stm:
                            if elm2.tag == Q_NAMES['saml2:AuthnContextClassRef']:
                                response.level_of_assurance = LevelOfAssurance(elm2.text)

    def __str__(self) -> str:
        return 'relay_state = {!r}, document = {}'.format(
            self.relay_state, dump_xml(self.document).decode('utf-8') if self.document else 'None')


def decrypt_xml(tree: ElementTree, key_file: str) -> None:
    """
    Decrypt a XML document.

    :param tree: The XML document to decrypt.
    :param key_file: A path to an encryption key file.
    """
    encrypted_elements = tree.findall(".//{%s}EncryptedData" % NAMESPACES['xmlenc'])
    if encrypted_elements:
        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(key_file, xmlsec.constants.KeyDataFormatPem))
        enc_ctx = xmlsec.EncryptionContext(manager)
        for elm in encrypted_elements:
            enc_ctx.decrypt(elm)

        # Fix pretty printing
        for elm in tree.iter():
            if elm.tail is not None and elm.tail.isspace():
                elm.tail = None
            if elm.text is not None and elm.text.isspace():
                elm.text = None


def create_eidas_attribute(parent: Element, name: str, required: bool) -> Element:
    """Create an eIDAS requested attribute element."""
    attribute = ATTRIBUTE_MAP.get(name)
    return SubElement(parent, Q_NAMES['eidas:RequestedAttribute'], {
        'Name': name,
        'FriendlyName': attribute.friendly_name if attribute else name.rsplit('/', 1)[-1],
        'NameFormat': attribute.name_format if attribute else EIDAS_ATTRIBUTE_NAME_FORMAT,
        'isRequired': 'true' if required else 'false',
    })
