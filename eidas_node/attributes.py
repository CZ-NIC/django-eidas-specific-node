"""eIDAS attributes."""
from collections import namedtuple
from itertools import chain
from typing import Dict, List

Attribute = namedtuple('Attribute', 'name_uri, name_format, friendly_name, required')

EIDAS_NATURAL_PERSON_PREFIX = 'http://eidas.europa.eu/attributes/naturalperson/'
EIDAS_LEGAL_PERSON_PREFIX = 'http://eidas.europa.eu/attributes/legalperson/'

EIDAS_ATTRIBUTE_NAME_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'

EIDAS_NATURAL_PERSON_ATTRIBUTES = [
    Attribute(EIDAS_NATURAL_PERSON_PREFIX + name, EIDAS_ATTRIBUTE_NAME_FORMAT, friendly, required)
    for name, friendly, required in [
        ('PersonIdentifier', 'PersonIdentifier', True),
        ('CurrentFamilyName', 'FamilyName', True),
        ('CurrentGivenName', 'FirstName', True),
        ('DateOfBirth', 'DateOfBirth', True),
        ('BirthName', 'BirthName', False),
        ('PlaceOfBirth', 'PlaceOfBirth', False),
        ('CurrentAddress', 'CurrentAddress', False),
        ('Gender', 'Gender', False),
    ]]  # type: List[Attribute]

EIDAS_LEGAL_PERSON_ATTRIBUTES = [
    Attribute(EIDAS_LEGAL_PERSON_PREFIX + name, EIDAS_ATTRIBUTE_NAME_FORMAT, name, False)
    for name in [
        'LegalPersonIdentifier',
        'LegalAddress',
        'LegalName',
        'VATRegistration',
        'TaxReference',
        'BusinessCodes',
        'LEI',
        'EORI',
        'SEED',
        'SIC',
        'D-2012-17-EUIdentifier',
    ]]  # type: List[Attribute]

ATTRIBUTE_MAP = {
    item.name_uri: item for item in chain(EIDAS_NATURAL_PERSON_ATTRIBUTES, EIDAS_LEGAL_PERSON_ATTRIBUTES)
}  # type: Dict[str, Attribute]
