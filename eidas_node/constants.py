"""Constants and enumerations."""
from enum import Enum, unique

TOKEN_ID_PREFIX = 'T'


@unique
class LevelOfAssurance(str, Enum):
    """Level of assurance required to fulfil the request."""

    LOW = 'http://eidas.europa.eu/LoA/low'
    SUBSTANTIAL = 'http://eidas.europa.eu/LoA/substantial'
    HIGH = 'http://eidas.europa.eu/LoA/high'


@unique
class NameIdFormat(str, Enum):
    """Required identifier format."""

    PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
    TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'


@unique
class ServiceProviderType(str, Enum):
    """The sector of a service provider."""

    PUBLIC = 'public'
    PRIVATE = 'private'


@unique
class StatusCode(str, Enum):
    """SAML2 defined status code."""

    SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
    """Authentication success."""
    REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester'
    """Authentication failure: the requester did something wrong."""
    RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder'
    """Authentication failure: error at the responder side."""


@unique
class SubStatusCode(str, Enum):
    """SAML2 defined sub status code used in case of failure."""

    AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
    INVALID_ATTR_NAME_OR_VALUE = 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue'
    INVALID_NAME_ID_POLICY = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy'
    VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'
    REQUEST_DENIED = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied'
