"""Models of eidas_node."""

import hashlib
import hmac
from base64 import b64decode, b64encode
from collections import OrderedDict
from datetime import datetime
from typing import Optional, cast

from lxml import etree
from lxml.etree import Element, QName

from eidas_node.constants import LevelOfAssurance, NameIdFormat, ServiceProviderType, StatusCode, SubStatusCode
from eidas_node.datamodels import DataModel, XMLDataModel
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.utils import create_eidas_timestamp, parse_eidas_timestamp
from eidas_node.xml import get_element_path


class LightToken(DataModel):
    """eIDAS-Node Light Token.

    See eIDAS-Node National IdP and SP Integration Guide version 2.3: 4.4.1. Implementing the LightToken.
    """

    FIELDS = ["id", "issuer", "created"]
    id: str
    """A unique identifier to reference the real data object (LightRequest/LightResponse)."""
    issuer: str
    """A simple text string that helps identify (debug) which component is sending the redirect."""
    created: datetime
    """A timestamp showing when the LightToken was created."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(str, "id", "issuer", required=True)
        self.validate_fields(datetime, "created", required=True)
        for field in "id", "issuer":
            if "|" in getattr(self, field):
                raise ValidationError({field: 'Character "|" not allowed.'})

    def digest(self, hash_algorithm: str, secret: str) -> bytes:
        """Calculate the digest of the token.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Digest as raw bytes (not base64 encoded).
        :raise ValidationError: If token data are invalid.
        """
        self.validate()
        assert self.id is not None  # noqa: S101
        assert self.issuer is not None  # noqa: S101
        data = "|".join((self.id, self.issuer, create_eidas_timestamp(cast(datetime, self.created)), secret))
        algorithm = hashlib.new(hash_algorithm)
        algorithm.update(data.encode("utf-8"))
        return algorithm.digest()

    def encode(self, hash_algorithm: str, secret: str) -> bytes:
        """Encode token for transmission.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Base64 encoded token as bytes.
        :raise ValidationError: If token data are invalid.
        """
        digest = b64encode(self.digest(hash_algorithm, secret)).decode("ascii")
        assert self.id is not None  # noqa: S101
        assert self.issuer is not None  # noqa: S101
        data = "|".join((self.issuer, self.id, create_eidas_timestamp(cast(datetime, self.created)), digest))
        return b64encode(data.encode("utf-8"))

    @classmethod
    def decode(cls, encoded_token: bytes, hash_algorithm: str, secret: str, max_size: int = 1024) -> "LightToken":
        """Decode encoded token and check the validity and digest.

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
            raise ParseError("Maximal token size exceeded.")
        data = b64decode(encoded_token, validate=True).decode("utf-8")
        try:
            issuer, token_id, timestamp, digest_base64 = data.split("|")
        except ValueError as e:
            raise ParseError("Token has wrong number of parts: {}.".format(e.args[0])) from e

        token = LightToken(issuer=issuer, id=token_id, created=parse_eidas_timestamp(timestamp))
        token.validate()

        provided_digest = b64decode(digest_base64.encode("ascii"))
        valid_digest = token.digest(hash_algorithm, secret)
        if not hmac.compare_digest(valid_digest, provided_digest):
            raise SecurityError("Light token has invalid digest.")
        return token


class LightRequest(XMLDataModel):
    """A request sent to/received from the generic part of eIDAS-Node."""

    FIELDS = [
        "citizen_country_code",
        "id",
        "issuer",
        "level_of_assurance",
        "name_id_format",
        "provider_name",
        "sp_type",
        "relay_state",
        "sp_country_code",
        "requested_attributes",
        "requester_id",
    ]
    ROOT_ELEMENT = "lightRequest"
    ROOT_NS = "http://cef.eidas.eu/LightRequest"
    citizen_country_code: Optional[str] = None
    """Country code of the requesting citizen. ISO ALPHA-2 format."""
    id: Optional[str] = None
    """Internal unique ID that will be used to correlate the response."""
    issuer: Optional[str] = None
    """Issuer of the LightRequest or originating SP - not used in version 2.0."""
    level_of_assurance: Optional[LevelOfAssurance] = None
    """Level of assurance required to fulfil the request"""
    name_id_format: Optional[NameIdFormat] = None
    """Optional instruction to the IdP that identifier format is requested (if supported)."""
    provider_name: Optional[str] = None
    """Free format text identifier of service provider initiating the request."""
    sp_type: Optional[ServiceProviderType] = None
    """Optional element specifying the sector of the SP or the Connector."""
    relay_state: Optional[str] = None
    """Optional state information expected to be returned with the LightResponse pair."""
    sp_country_code: Optional[str] = None
    """The code of requesting country."""
    requested_attributes: Optional[dict[str, list[str]]] = None
    """The list of requested attributes."""
    requester_id: Optional[str] = None
    """Identification of service provider"""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(str, "citizen_country_code", "id", required=True)
        self.validate_fields(str, "issuer", "provider_name", "relay_state", "sp_country_code", required=False)
        self.validate_fields(LevelOfAssurance, "level_of_assurance", required=True)
        self.validate_fields(NameIdFormat, "name_id_format", required=False)
        self.validate_fields(ServiceProviderType, "sp_type", required=False)
        validate_attributes(self, "requested_attributes")

    def deserialize_level_of_assurance(self, elm: Element) -> Optional[LevelOfAssurance]:
        """Deserialize field 'level_of_assurance'."""
        return LevelOfAssurance(elm.text) if elm.text else None

    def deserialize_name_id_format(self, elm: Element) -> Optional[NameIdFormat]:
        """Deserialize field 'name_id_format'."""
        return NameIdFormat(elm.text) if elm.text else None

    def deserialize_sp_type(self, elm: Element) -> Optional[ServiceProviderType]:
        """Deserialize field 'sp_type'."""
        return ServiceProviderType(elm.text) if elm.text else None

    def deserialize_requested_attributes(self, elm: Element) -> dict[str, list[str]]:
        """Deserialize field 'requested_attributes'."""
        return deserialize_attributes(elm)

    def serialize_requested_attributes(self, root: Element, tag: str, attributes: dict[str, list[str]]) -> None:
        """Serialize field 'requested_attributes'."""
        serialize_attributes(root, tag, attributes)


class Status(XMLDataModel):
    """Complex element to provide status information from IdP."""

    FIELDS = ["failure", "status_code", "sub_status_code", "status_message"]
    ROOT_ELEMENT = "status"
    failure: bool = False
    """Whether the authentication request has failed."""
    status_code: Optional[StatusCode] = None
    """SAML2 defined status code."""
    sub_status_code: Optional[SubStatusCode] = None
    """SAML2 defined sub status code used in case of failure."""
    status_message: Optional[str] = None
    """An optional status message."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(bool, "failure", required=True)
        self.validate_fields(StatusCode, "status_code", required=False)
        self.validate_fields(SubStatusCode, "sub_status_code", required=False)
        self.validate_fields(str, "status_message", required=False)

    def deserialize_failure(self, elm: Element) -> Optional[bool]:
        """Deserialize field 'failure'."""
        return elm.text.lower() == "true" if elm.text else None

    def deserialize_status_code(self, elm: Element) -> Optional[StatusCode]:
        """Deserialize field 'status_code'."""
        return StatusCode(elm.text) if elm.text else None

    def deserialize_sub_status_code(self, elm: Element) -> Optional[SubStatusCode]:
        """Deserialize field 'sub_status_code'."""
        if elm.text and "##" in elm.text:
            return None
        return SubStatusCode(elm.text) if elm.text else None


class LightResponse(XMLDataModel):
    """A response sent to/received from the generic part of eIDAS-Node."""

    FIELDS = [
        "id",
        "in_response_to_id",
        "issuer",
        "ip_address",
        "relay_state",
        "subject",
        "subject_name_id_format",
        "level_of_assurance",
        "status",
        "attributes",
        "consent",
    ]
    ROOT_ELEMENT = "lightResponse"
    ROOT_NS = "http://cef.eidas.eu/LightResponse"
    id: Optional[str] = None
    """Internal unique ID."""
    in_response_to_id: Optional[str] = None
    """The original unique ID of the Request this Response is issued for."""
    issuer: Optional[str] = None
    """Issuer of the LightRequest or originating SP - not used in version 2.0."""
    ip_address: Optional[str] = None
    """Optional IP address of the user agent as seen on IdP"""
    relay_state: Optional[str] = None
    """Optional state information to return to the Consumer."""
    subject: Optional[str] = None
    """Subject of the Assertion for the eIDAS SAML Response."""
    subject_name_id_format: Optional[NameIdFormat] = None
    """Format of the identifier attribute."""
    level_of_assurance: Optional[LevelOfAssurance] = None
    """Level of assurance required to fulfil the request"""
    status: Optional[Status] = None
    """Complex element to provide status information from IdP."""
    attributes: Optional[dict[str, list[str]]] = None
    """The list of attributes and their values."""
    consent: Optional[str] = None
    """Type of conset specified by user"""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(Status, "status", required=True)
        cast(Status, self.status).validate()
        validate_attributes(self, "attributes")
        if cast(Status, self.status).failure:
            self.validate_fields(str, "id", "in_response_to_id", required=True)
            self.validate_fields(str, "subject", "issuer", "ip_address", "relay_state", required=False)
            self.validate_fields(NameIdFormat, "subject_name_id_format", required=False)
            self.validate_fields(LevelOfAssurance, "level_of_assurance", required=False)
        else:
            self.validate_fields(str, "id", "in_response_to_id", "subject", required=True)
            self.validate_fields(str, "issuer", "ip_address", "relay_state", required=False)
            self.validate_fields(NameIdFormat, "subject_name_id_format", required=True)
            self.validate_fields(LevelOfAssurance, "level_of_assurance", required=True)

    def deserialize_subject_name_id_format(self, elm: Element) -> Optional[NameIdFormat]:
        """Deserialize field 'subject_name_name_id_format'."""
        return NameIdFormat(elm.text) if elm.text else None

    def deserialize_level_of_assurance(self, elm: Element) -> Optional[LevelOfAssurance]:
        """Deserialize field 'level_of_assurance'."""
        return LevelOfAssurance(elm.text) if elm.text else None

    def deserialize_status(self, elm: Element) -> Status:
        """Deserialize field 'status'."""
        return Status.load_xml(elm)

    def deserialize_attributes(self, elm: Element) -> dict[str, list[str]]:
        """Deserialize field 'attributes'."""
        return deserialize_attributes(elm)

    def serialize_attributes(self, root: etree.Element, tag: str, attributes: dict[str, list[str]]) -> None:
        """Serialize field 'attributes'."""
        return serialize_attributes(root, tag, attributes)


def validate_attributes(model: DataModel, field_name: str) -> None:
    """Validate eIDAS attributes."""
    model.validate_fields(dict, field_name, required=True)
    attributes: dict[str, list[str]] = getattr(model, field_name)
    for key, values in attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValidationError({field_name: "All keys must be strings."})
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValidationError({field_name: "All values must be lists of strings."})


def serialize_attributes(parent_element: etree.Element, tag: str, attributes: Optional[dict[str, list[str]]]) -> None:
    """Serialize eIDAS attributes."""
    if attributes is not None:
        elm = etree.SubElement(parent_element, tag)
        for name, values in attributes.items():
            attribute = etree.SubElement(elm, "attribute")
            etree.SubElement(attribute, "definition").text = name
            for value in values:
                etree.SubElement(attribute, "value").text = value


def deserialize_attributes(attributes_elm: Element) -> dict[str, list[str]]:
    """Deserialize eIDAS attributes."""
    attributes: dict[str, list[str]] = OrderedDict()
    for attribute in attributes_elm:
        if QName(attribute.tag).localname != "attribute":
            raise ValidationError({get_element_path(attribute): "Unexpected element {!r}".format(attribute.tag)})
        if not len(attribute):
            raise ValidationError({get_element_path(attribute): "Missing attribute.definition element."})
        definition = attribute[0]
        if QName(definition.tag).localname != "definition":
            raise ValidationError({get_element_path(definition): "Unexpected element {!r}".format(definition.tag)})

        values = attributes[definition.text] = []
        for value in attribute[1:]:
            if QName(value.tag).localname != "value":
                raise ValidationError({get_element_path(value): "Unexpected element {!r}".format(value.tag)})
            values.append(value.text)
    return attributes
