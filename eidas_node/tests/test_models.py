from base64 import b64decode
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Dict, Set, cast
from unittest import mock

from django.test import SimpleTestCase

from eidas_node.constants import LevelOfAssurance, NameIdFormat, ServiceProviderType
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.models import LightRequest, LightToken
from eidas_node.utils import dump_xml, parse_xml

DATA_DIR = Path(__file__).parent / 'data'  # type: Path

LIGHT_REQUEST_DICT = OrderedDict([
        ('citizen_country_code', 'CA'),
        ('id', 'test-light-request-id'),
        ('issuer', 'test-light-request-issuer'),
        ('level_of_assurance', LevelOfAssurance.LOW),
        ('name_id_format', NameIdFormat.UNSPECIFIED),
        ('provider_name', 'DEMO-SP-CA'),
        ('sp_type', ServiceProviderType.PUBLIC),
        ('relay_state', 'relay123'),
        ('origin_country_code', None),
        ('requested_attributes', OrderedDict([
            ('http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier', []),
            ('http://eidas.europa.eu/attributes/legalperson/EORI', []),
            ('http://eidas.europa.eu/attributes/legalperson/LEI', []),
            ('http://eidas.europa.eu/attributes/legalperson/LegalName', []),
            ('http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress', []),
            ('http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier', []),
            ('http://eidas.europa.eu/attributes/legalperson/SEED', []),
            ('http://eidas.europa.eu/attributes/legalperson/SIC', []),
            ('http://eidas.europa.eu/attributes/legalperson/TaxReference', []),
            ('http://eidas.europa.eu/attributes/legalperson/VATRegistrationNumber', []),
            ('http://eidas.europa.eu/attributes/naturalperson/BirthName', []),
            ('http://eidas.europa.eu/attributes/naturalperson/CurrentAddress', [
                '\n        PEFkZHJlc3NJZD5odHRwOi8vYWRkcmVzcy5leGFtcGxlL2lkL2JlL2VoMTFhYTwvQWRkcmVzc0lk\n'
                '        Pg0KPFBvQm94PjEyMzQ8L1BvQm94ID4NCjxMb2NhdG9yRGVzaWduYXRvcj4yODwvTG9jYXRvckRlc2lnbmF\n'
                '        0b3I+DQo8TG9jYXRvck5hbWU+RElHSVQgYnVpbGRpbmc8L0xvY2F0b3JOYW1lPg0KPEN2QWRkcmVzc0FyZW\n'
                '        E+RXR0ZXJiZWVrPC9DdkFkZHJlc3NBcmVhPg0KPFRob3JvdWdoZmFyZT5SdWUgQmVsbGlhcmQ8L1Rob3Jvd\n'
                '        WdoZmFyZT4NCjxQb3N0TmFtZT5FVFRFUkJFRUsgQ0hBU1NFPC9Qb3N0TmFtZT4NCjxBZG1pblVuaXRGaXJz\n'
                '        dExpbmU+QkU8L0FkbWluVW5pdEZpcnN0TGluZT4NCjxBZG1pblVuaXRTZWNvbmRMaW5lPkVUVEVSQkVFSzw\n'
                '        vQWRtaW5Vbml0U2Vjb25kTGluZT4NCjxQb3N0Q29kZT4xMDQwPC9Qb3N0Q29kZT4NCjxGdWxsQ3ZhZGRyZX\n'
                '        NzPlJ1ZSBCZWxsaWFyZCAyOFxuQkUtMTA0MCBFdHRlcmJlZWs8L0Z1bGxDdmFkZHJlc3M+\n      ']),
            ('http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', []),
            ('http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', [
                'Antonio', 'Lucio', 'Vivaldi']),
            ('http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', []),
            ('http://eidas.europa.eu/attributes/naturalperson/Gender', []),
            ('http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', ['Vivaldi-987654321']),
            ('http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth', []),
            ('http://eidas.europa.eu/attributes/legalperson/LegalAdditionalAttribute', []),
            ('http://eidas.europa.eu/attributes/naturalperson/AdditionalAttribute', []),
        ]))])


class ValidationMixin:
    # Model to validate
    MODEL = None  # type: type
    # Optional fields - can be None
    OPTIONAL = set()  # type: Set[str]
    # Example of valid data
    VALID_DATA = None  # type: Dict[str, Any]
    # Invalid data for basic type checks. Extra checks must have own test method.
    INVALID_DATA = None  # type: Dict[str, Any]

    def test_valid(self):
        self.MODEL(**self.VALID_DATA).validate()

    def test_required(self):
        t = cast(SimpleTestCase, self)
        for name in self.VALID_DATA:
            required = name not in self.OPTIONAL
            with t.subTest(name=name, required=required):
                data = self.VALID_DATA.copy()
                del data[name]
                if required:
                    t.assertRaises(ValidationError, self.MODEL(**data).validate)
                else:
                    self.MODEL(**self.VALID_DATA).validate()

    def test_invalid(self):
        t = cast(SimpleTestCase, self)
        for name in self.INVALID_DATA:
            with t.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] = self.INVALID_DATA[name]
                t.assertRaises(ValidationError, self.MODEL(**data).validate)


class TestLightToken(ValidationMixin, SimpleTestCase):
    MODEL = LightToken
    VALID_DATA = {
        'id': '852a64c0-8ac1-445f-b0e1-992ada493033',
        'issuer': 'specificCommunicationDefinitionConnectorRequest',
        'created': datetime(2017, 12, 11, 14, 12, 5, 148000),
    }
    INVALID_DATA = {
        'id': 123,
        'issuer': b'specificCommunicationDefinitionConnectorRequest',
        'created': '2017-12-11 14:12:05 148',
    }
    SECRET = 'mySecretConnectorRequest'
    ENCODED_TOKEN = (b'c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0'
                     b'0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk'
                     b'lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWUU9')

    def get_token(self, **kwargs) -> LightToken:
        data = self.VALID_DATA.copy()
        data.update(**kwargs)
        return LightToken(**data)

    def test_pipe_character_not_allowed(self):
        for name in 'id', 'issuer':
            with self.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] += '|pipe'
                self.assertRaises(ValidationError, self.MODEL(**data).validate)

    def test_digest(self):
        token = self.get_token()
        digest = token.digest('sha256', self.SECRET)
        expected_digest = b64decode(b'7M8p+uP8CKXuMi2IqSda1tg452WlRvcOSwu0dcisSYE=')
        self.assertEqual(expected_digest, digest)

    def test_encode(self):
        token = self.get_token()
        self.assertEqual(token.encode('sha256', self.SECRET), self.ENCODED_TOKEN)

    def test_decode_ok(self):
        self.assertEqual(LightToken.decode(self.ENCODED_TOKEN, 'sha256', self.SECRET), self.get_token())

    def test_decode_validation_error(self):
        with mock.patch.object(LightToken, 'validate'):
            encoded = self.get_token(issuer='').encode('sha256', self.SECRET)

        with self.assertRaisesMessage(ValidationError, 'Must be str, not NoneType'):
            LightToken.decode(encoded, 'sha256', self.SECRET)

    def test_decode_max_size_exceeded(self):
        with self.assertRaisesMessage(ParseError, 'Maximal token size exceeded.'):
            LightToken.decode(self.ENCODED_TOKEN * 100, 'sha256', self.SECRET)

    def test_decode_wrong_number_of_parts(self):
        token = self.get_token(issuer='specificCommunicationDefinitionConnectorRequest|extra')
        with mock.patch.object(LightToken, 'validate'):
            encoded = token.encode('sha256', self.SECRET)

        with self.assertRaisesMessage(ParseError, 'wrong number of parts'):
            LightToken.decode(encoded, 'sha256', self.SECRET)

    def test_decode_wrong_secret(self):
        with self.assertRaisesMessage(SecurityError, 'invalid digest'):
            LightToken.decode(self.ENCODED_TOKEN, 'sha256', 'Dycky Most!')

    def test_decode_wrong_digest(self):
        encoded = (b'c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0'
                   b'0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk'
                   b'lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWWs9')
        with self.assertRaisesMessage(SecurityError, 'invalid digest'):
            LightToken.decode(encoded, 'sha256', self.SECRET)


class TestLightRequest(ValidationMixin, SimpleTestCase):
    MODEL = LightRequest
    OPTIONAL = {'issuer', 'name_id_format', 'provider_name', 'sp_type', 'relay_state', 'origin_country_code'}
    VALID_DATA = {
        'citizen_country_code': 'CZ',
        'origin_country_code': 'CZ',
        'id': 'uuid',
        'issuer': 'MyIssuer',
        'level_of_assurance': LevelOfAssurance.LOW,
        'name_id_format': NameIdFormat.PERSISTENT,
        'provider_name': 'MyProvider',
        'sp_type': ServiceProviderType.PUBLIC,
        'relay_state': 'state 123',
        'requested_attributes': {'attr1': [], 'attr2': ['value1', 'value2']},
    }
    INVALID_DATA = {
        'citizen_country_code': 1,
        'origin_country_code': 1,
        'id': 1,
        'issuer': 1,
        'level_of_assurance': LevelOfAssurance.LOW.value,
        'name_id_format': NameIdFormat.PERSISTENT.value,
        'provider_name': 1,
        'sp_type': ServiceProviderType.PUBLIC.value,
        'relay_state': 1,
        'requested_attributes': ['attr1'],
    }

    def test_attributes(self):
        field_name = 'requested_attributes'
        invalid_attributes = (
            {b'attr1': []},
            {'attr1': None},
            {'attr1': [None]},
            {'attr1': ['value1', None]},
        )  # type: tuple
        data = self.VALID_DATA.copy()
        for i, invalid in enumerate(invalid_attributes):
            with self.subTest(i=i):
                data[field_name] = invalid
                self.assertRaises(ValidationError, self.MODEL(**data).validate)

    def test_load_xml_full_sample(self):
        with cast(BinaryIO, (DATA_DIR / 'light_request.xml').open('rb')) as f:
            request = LightRequest.load_xml(parse_xml(f))
        self.assertEqual(request, LightRequest(**LIGHT_REQUEST_DICT))

    def test_load_xml_minimal_sample(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / 'light_request_minimal.xml').open('rb')) as f:
            request = LightRequest.load_xml(parse_xml(f))

        self.assertEqual(request.citizen_country_code, 'CA')
        self.assertEqual(request.id, 'test-light-request-id')
        self.assertIsNone(request.issuer)
        self.assertEqual(request.level_of_assurance, LevelOfAssurance.LOW)
        self.assertIsNone(request.name_id_format)
        self.assertIsNone(request.provider_name)
        self.assertIsNone(request.sp_type)
        self.assertIsNone(request.relay_state)
        self.assertEqual(request.requested_attributes, {})

    def test_load_xml_wrong_root_element(self):
        data = parse_xml(b'<lightResponse></lightResponse>')
        with self.assertRaisesMessage(ValidationError,
                                      '\'<lightResponse>\': "Invalid root element \'lightResponse\'."'):
            LightRequest.load_xml(data)

    def test_load_xml_unknown_element(self):
        data = parse_xml(b'<lightRequest><myField>data</myField></lightRequest>')
        with self.assertRaisesMessage(ValidationError, '\'<lightRequest><myField>\': "Unknown element \'myField\'."'):
            LightRequest.load_xml(data)

    def test_load_xml_attributes_unexpected_element(self):
        data = parse_xml(b'<lightRequest><requestedAttributes><myField>data</myField>'
                         b'</requestedAttributes></lightRequest>')
        with self.assertRaisesMessage(ValidationError,
                                      '\'<lightRequest><requestedAttributes><myField>\': '
                                      '"Unexpected element \'myField\'"'):
            LightRequest.load_xml(data)

    def test_load_xml_attributes_definition_element(self):
        data = parse_xml(b'<lightRequest><requestedAttributes><attribute>data</attribute>'
                         b'</requestedAttributes></lightRequest>')
        with self.assertRaisesMessage(ValidationError,
                                      "'<lightRequest><requestedAttributes><attribute>': "
                                      "'Missing attribute.definition element.'"):
            LightRequest.load_xml(data)
        data = parse_xml(b'<lightRequest><requestedAttributes><attribute><foo>data</foo>'
                         b'</attribute></requestedAttributes></lightRequest>')
        with self.assertRaisesMessage(ValidationError,
                                      '\'<lightRequest><requestedAttributes><attribute><foo>\': '
                                      '"Unexpected element \'foo\'"'):
            LightRequest.load_xml(data)

    def test_load_xml_attribute_values_unexpected_element(self):
        data = parse_xml(b'<lightRequest><requestedAttributes><attribute><definition>data</definition><foo/>'
                         b'</attribute></requestedAttributes></lightRequest>')
        with self.assertRaisesMessage(ValidationError,
                                      '\'<lightRequest><requestedAttributes><attribute><foo>\': '
                                      '"Unexpected element \'foo\'"'):
            LightRequest.load_xml(data)

    def test_export_xml_full_sample(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / 'light_request.xml').open('rb')) as f:
            data = f.read()
            request = LightRequest.load_xml(parse_xml(data))
        self.assertEqual(dump_xml(request.export_xml()), data)

    def test_export_xml_minimal_sample(self):
        request = LightRequest(
            citizen_country_code='CA', id='test-light-request-id',
            level_of_assurance=LevelOfAssurance.LOW, requested_attributes={})
        with cast(BinaryIO, (DATA_DIR / 'light_request_minimal.xml').open('rb')) as f:
            data = f.read()
        self.assertEqual(dump_xml(request.export_xml()), data)
