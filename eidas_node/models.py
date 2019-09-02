"""Models of eidas_node."""
import hashlib
import hmac
from base64 import b64decode, b64encode
from collections import OrderedDict
from datetime import datetime
from typing import Dict, List, Optional

from lxml import etree
from lxml.etree import Element

from eidas_node.constants import LevelOfAssurance, NameIdFormat, ServiceProviderType, StatusCode, SubStatusCode
from eidas_node.datamodels import DataModel, XMLDataModel
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.utils import create_eidas_timestamp, get_element_path, parse_eidas_timestamp


class LightToken(DataModel):
    """
    eIDAS-Node Light Token.

    See eIDAS-Node National IdP and SP Integration Guide version 2.3: 4.4.1. Implementing the LightToken.
    """

    FIELDS = ['id', 'issuer', 'created']
    id = None  # type: str
    """A unique identifier to reference the real data object (LightRequest/LightResponse)."""
    issuer = None  # type: str
    """A simple text string that helps identify (debug) which component is sending the redirect."""
    created = None  # type: datetime
    """A timestamp showing when the LightToken was created."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(str, 'id', 'issuer', required=True)
        self.validate_fields(datetime, 'created', required=True)
        for field in 'id', 'issuer':
            if '|' in getattr(self, field):
                raise ValidationError({field: 'Character "|" not allowed.'})

    def digest(self, hash_algorithm: str, secret: str) -> bytes:
        """
        Calculate the digest of the token.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Digest as raw bytes (not base64 encoded).
        :raise ValidationError: If token data are invalid.
        """
        self.validate()
        data = '|'.join((self.id, self.issuer, create_eidas_timestamp(self.created), secret))
        algorithm = hashlib.new(hash_algorithm)
        algorithm.update(data.encode('utf-8'))
        return algorithm.digest()

    def encode(self, hash_algorithm: str, secret: str) -> bytes:
        """
        Encode token for transmission.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Base64 encoded token as bytes.
        :raise ValidationError: If token data are invalid.
        """
        digest = b64encode(self.digest(hash_algorithm, secret)).decode('ascii')
        data = '|'.join((self.issuer, self.id, create_eidas_timestamp(self.created), digest))
        return b64encode(data.encode('utf-8'))

    @classmethod
    def decode(cls, encoded_token: bytes, hash_algorithm: str, secret: str, max_size: int = 1024) -> 'LightToken':
        """
        Decode encoded token and check the validity and digest.

        :param encoded_token:  Base64 encoded token.
        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :param max_size: The maximal size of the encoded token.
        :return: Decoded and validated token.
        :raise ParseError: If the token is malformed and cannot be decoded.
        :raise ValidationError: If the token can be decoded but model validation fails.
        :raise SecurityError: If the token digest is invalid.
        """
        if max_size and len(encoded_token) > max_size:
            raise ParseError('Maximal token size exceeded.')
        data = b64decode(encoded_token, validate=True).decode('utf-8')
        try:
            issuer, token_id, timestamp, digest_base64 = data.split('|')
        except ValueError as e:
            raise ParseError('Token has wrong number of parts: {}.'.format(e.args[0]))

        token = LightToken(issuer=issuer, id=token_id, created=parse_eidas_timestamp(timestamp))
        token.validate()

        provided_digest = b64decode(digest_base64.encode('ascii'))
        valid_digest = token.digest(hash_algorithm, secret)
        if not hmac.compare_digest(valid_digest, provided_digest):
            raise SecurityError('Light token has invalid digest.')
        return token


class LightRequest(XMLDataModel):
    """A request sent to/received from the generic part of eIDAS-Node."""

    FIELDS = ['citizen_country_code', 'id', 'issuer', 'level_of_assurance', 'name_id_format', 'provider_name',
              'sp_type', 'relay_state', 'origin_country_code', 'requested_attributes']
    ROOT_ELEMENT = 'lightRequest'
    citizen_country_code = None  # type: str
    """Country code of the requesting citizen. ISO ALPHA-2 format."""
    id = None  # type: str
    """Internal unique ID that will be used to correlate the response."""
    issuer = None  # type: Optional[str]
    """Issuer of the LightRequest or originating SP - not used in version 2.0."""
    level_of_assurance = None  # type: LevelOfAssurance
    """Level of assurance required to fulfil the request"""
    name_id_format = None  # type: Optional[NameIdFormat]
    """Optional instruction to the IdP that identifier format is requested (if supported)."""
    provider_name = None  # type: Optional[str]
    """Free format text identifier of service provider initiating the request."""
    sp_type = None  # type: Optional[ServiceProviderType]
    """Optional element specifying the sector of the SP or the Connector."""
    relay_state = None  # type: Optional[str]
    """Optional state information expected to be returned with the LightResponse pair."""
    origin_country_code = None  # type: Optional[str]
    """The code of requesting country."""
    requested_attributes = None  # type: Dict[str, List[str]]
    """The list of requested attributes."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(str, 'citizen_country_code', 'id', required=True)
        self.validate_fields(str, 'issuer', 'provider_name', 'relay_state', 'origin_country_code', required=False)
        self.validate_fields(LevelOfAssurance, 'level_of_assurance', required=True)
        self.validate_fields(NameIdFormat, 'name_id_format', required=False)
        self.validate_fields(ServiceProviderType, 'sp_type', required=False)
        validate_attributes(self, 'requested_attributes')

    def deserialize_level_of_assurance(self, elm: Element) -> Optional[LevelOfAssurance]:
        """Deserialize field 'level_of_assurance'."""
        return LevelOfAssurance(elm.text) if elm.text else None

    def deserialize_name_id_format(self, elm: Element) -> Optional[NameIdFormat]:
        """Deserialize field 'name_id_format'."""
        return NameIdFormat(elm.text) if elm.text else None

    def deserialize_sp_type(self, elm: Element) -> Optional[ServiceProviderType]:
        """Deserialize field 'sp_type'."""
        return ServiceProviderType(elm.text) if elm.text else None

    def deserialize_requested_attributes(self, elm: Element) -> Dict[str, List[str]]:
        """Deserialize field 'requested_attributes'."""
        return deserialize_attributes(elm)

    def serialize_requested_attributes(self, root: Element, tag: str, attributes: Dict[str, List[str]]) -> None:
        """Serialize field 'requested_attributes'."""
        serialize_attributes(root, tag, attributes)


class Status(XMLDataModel):
    """Complex element to provide status information from IdP."""

    FIELDS = ['failure', 'status_code', 'sub_status_code', 'status_message']
    ROOT_ELEMENT = 'status'
    failure = None  # type: bool
    """Whether the authentication request has failed."""
    status_code = None  # type: Optional[StatusCode]
    """SAML2 defined status code."""
    sub_status_code = None  # type: Optional[SubStatusCode]
    """SAML2 defined sub status code used in case of failure."""
    status_message = None  # type: Optional[str]
    """An optional status message."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(bool, 'failure', required=True)
        self.validate_fields(StatusCode, 'status_code', required=False)
        self.validate_fields(SubStatusCode, 'sub_status_code', required=False)
        self.validate_fields(str, 'status_message', required=False)

    def deserialize_failure(self, elm: Element) -> Optional[bool]:
        """Deserialize field 'failure'."""
        return elm.text.lower() == 'true' if elm.text else None

    def deserialize_status_code(self, elm: Element) -> Optional[StatusCode]:
        """Deserialize field 'status_code'."""
        return StatusCode(elm.text) if elm.text else None

    def deserialize_sub_status_code(self, elm: Element) -> Optional[SubStatusCode]:
        """Deserialize field 'sub_status_code'."""
        return SubStatusCode(elm.text) if elm.text else None


class LightResponse(XMLDataModel):
    """A response sent to/received from the generic part of eIDAS-Node."""

    FIELDS = ['id', 'in_response_to_id', 'issuer', 'ip_address', 'relay_state', 'subject',
              'subject_name_id_format', 'level_of_assurance', 'status', 'attributes']
    ROOT_ELEMENT = 'lightResponse'
    id = None  # type: str
    """Internal unique ID."""
    in_response_to_id = None  # type: str
    """The original unique ID of the Request this Response is issued for."""
    issuer = None  # type: Optional[str]
    """Issuer of the LightRequest or originating SP - not used in version 2.0."""
    ip_address = None  # type: Optional[str]
    """Optional IP address of the user agent as seen on IdP"""
    relay_state = None  # type: Optional[str]
    """Optional state information to return to the Consumer."""
    subject = None  # type: str
    """Subject of the Assertion for the eIDAS SAML Response."""
    subject_name_id_format = None  # type: NameIdFormat
    """Format of the identifier attribute."""
    level_of_assurance = None  # type: LevelOfAssurance
    """Level of assurance required to fulfil the request"""
    status = None  # type: Status
    """Complex element to provide status information from IdP."""
    attributes = None  # type: Dict[str, List[str]]
    """The list of attributes and their values."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(Status, 'status', required=True)
        self.status.validate()
        self.validate_fields(str, 'id', 'in_response_to_id', 'subject', required=True)
        self.validate_fields(str, 'issuer', 'ip_address', 'relay_state', required=False)
        self.validate_fields(NameIdFormat, 'subject_name_id_format', required=True)
        self.validate_fields(LevelOfAssurance, 'level_of_assurance', required=True)
        validate_attributes(self, 'attributes')

    def deserialize_subject_name_id_format(self, elm: Element) -> Optional[NameIdFormat]:
        """Deserialize field 'subject_name_name_id_format'."""
        return NameIdFormat(elm.text) if elm.text else None

    def deserialize_level_of_assurance(self, elm: Element) -> Optional[LevelOfAssurance]:
        """Deserialize field 'level_of_assurance'."""
        return LevelOfAssurance(elm.text) if elm.text else None

    def deserialize_status(self, elm: Element) -> Status:
        """Deserialize field 'status'."""
        return Status.load_xml(elm)

    def deserialize_attributes(self, elm: Element) -> Dict[str, List[str]]:
        """Deserialize field 'attributes'."""
        return deserialize_attributes(elm)

    def serialize_attributes(self, root: etree.Element, tag: str, attributes: Dict[str, List[str]]) -> None:
        """Serialize field 'attributes'."""
        return serialize_attributes(root, tag, attributes)


def validate_attributes(model: DataModel, field_name: str) -> None:
    """Validate eIDAS attributes."""
    model.validate_fields(dict, field_name, required=True)
    attributes = getattr(model, field_name)  # type: Dict[str, List[str]]
    for key, values in attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValidationError({field_name: 'All keys must be strings.'})
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValidationError({field_name: 'All values must be lists of strings.'})


def serialize_attributes(parent_element: etree.Element, tag: str, attributes: Optional[Dict[str, List[str]]]) -> None:
    """Serialize eIDAS attributes."""
    if attributes is not None:
        elm = etree.SubElement(parent_element, tag)
        for name, values in attributes.items():
            attribute = etree.SubElement(elm, 'attribute')
            etree.SubElement(attribute, 'definition').text = name
            for value in values:
                etree.SubElement(attribute, 'value').text = value


def deserialize_attributes(attributes_elm: Element) -> Dict[str, List[str]]:
    """Deserialize eIDAS attributes."""
    attributes = OrderedDict()  # type: Dict[str, List[str]]
    for attribute in attributes_elm:
        if attribute.tag != 'attribute':
            raise ValidationError({get_element_path(attribute): 'Unexpected element {!r}'.format(attribute.tag)})
        if not len(attribute):
            raise ValidationError({get_element_path(attribute): 'Missing attribute.definition element.'})
        definition = attribute[0]
        if definition.tag != 'definition':
            raise ValidationError({get_element_path(definition): 'Unexpected element {!r}'.format(definition.tag)})

        values = attributes[definition.text] = []
        for value in attribute[1:]:
            if value.tag != 'value':
                raise ValidationError({get_element_path(value): 'Unexpected element {!r}'.format(value.tag)})
            values.append(value.text)
    return attributes
