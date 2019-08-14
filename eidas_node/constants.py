"""Constants and enumerations."""
from enum import Enum, unique


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
