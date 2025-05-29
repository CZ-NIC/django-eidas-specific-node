"""eIDAS attributes."""

from collections import namedtuple
from itertools import chain
from typing import Dict, List, Set

Attribute = namedtuple("Attribute", "name_uri, name_format, friendly_name, required")

EIDAS_NATURAL_PERSON_PREFIX = "http://eidas.europa.eu/attributes/naturalperson/"
EIDAS_LEGAL_PERSON_PREFIX = "http://eidas.europa.eu/attributes/legalperson/"

EIDAS_ATTRIBUTE_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

# eIDAS SAML Attribute Profile v1.2, Section 2.2 Attributes for Natural Persons
EIDAS_NATURAL_PERSON_ATTRIBUTES: List[Attribute] = [
    Attribute(EIDAS_NATURAL_PERSON_PREFIX + name, EIDAS_ATTRIBUTE_NAME_FORMAT, friendly, required)
    for name, friendly, required in [
        ("PersonIdentifier", "PersonIdentifier", True),
        ("CurrentFamilyName", "FamilyName", True),
        ("CurrentGivenName", "FirstName", True),
        ("DateOfBirth", "DateOfBirth", True),
        ("BirthName", "BirthName", False),
        ("PlaceOfBirth", "PlaceOfBirth", False),
        ("CurrentAddress", "CurrentAddress", False),
        ("Gender", "Gender", False),
    ]
]

# eIDAS SAML Attribute Profile v1.2, Section 2.3 Attributes for Legal Persons
EIDAS_LEGAL_PERSON_ATTRIBUTES: List[Attribute] = [
    Attribute(EIDAS_LEGAL_PERSON_PREFIX + name, EIDAS_ATTRIBUTE_NAME_FORMAT, friendly, False)
    for name, friendly in [
        ("LegalPersonIdentifier", "LegalPersonIdentifier"),
        ("LegalPersonAddress", "LegalAddress"),
        ("LegalName", "LegalName"),
        ("VATRegistrationNumber", "VATRegistration"),
        ("TaxReference", "TaxReference"),
        ("BusinessCodes", "BusinessCodes"),
        ("LEI", "LEI"),
        ("EORI", "EORI"),
        ("SEED", "SEED"),
        ("SIC", "SIC"),
        ("D-2012-17-EUIdentifier", "D-2012-17-EUIdentifier"),
    ]
]

ATTRIBUTE_MAP: Dict[str, Attribute] = {
    item.name_uri: item for item in chain(EIDAS_NATURAL_PERSON_ATTRIBUTES, EIDAS_LEGAL_PERSON_ATTRIBUTES)
}

MANDATORY_ATTRIBUTE_NAMES: Set[str] = {name for name, attribute in ATTRIBUTE_MAP.items() if attribute.required}
