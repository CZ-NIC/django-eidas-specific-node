"""Constants and enumerations."""

# This module must contain only constants and enums
# with basic types to be importable from settings.
from enum import Enum, unique

TOKEN_ID_PREFIX = "T"


@unique
class LevelOfAssurance(str, Enum):
    """Level of assurance required to fulfil the request."""

    LOW = "http://eidas.europa.eu/LoA/low"
    SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial"
    HIGH = "http://eidas.europa.eu/LoA/high"


@unique
class NameIdFormat(str, Enum):
    """Required identifier format."""

    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"


@unique
class ServiceProviderType(str, Enum):
    """The sector of a service provider."""

    PUBLIC = "public"
    PRIVATE = "private"


@unique
class StatusCode(str, Enum):
    """SAML2 defined status code."""

    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    """Authentication success."""
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    """Authentication failure: the requester did something wrong."""
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    """Authentication failure: error at the responder side."""


@unique
class SubStatusCode(str, Enum):
    """SAML2 defined sub status code used in case of failure."""

    AUTHN_FAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
    INVALID_ATTR_NAME_OR_VALUE = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
    INVALID_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
    VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
    REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"


@unique
class XmlBlockCipher(str, Enum):
    """XML encryption algorithms.

    Specification: https://www.w3.org/TR/xmlenc-core1/#sec-Alg-Block
    """

    TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
    AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
    AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
    # libxmlsec >= 1.2.27
    AES128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
    AES192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
    AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"


@unique
class XmlKeyTransport(str, Enum):
    """XML key transport algorithms.

    Specification: https://www.w3.org/TR/xmlenc-core1/#sec-Alg-KeyTransport
    """

    RSA = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
    RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    # Not supported by libxmlsec1 (1.2.29)
    # RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep'
