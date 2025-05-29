from base64 import b64decode
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Dict, Set, cast
from unittest import mock

from django.test import SimpleTestCase
from lxml.etree import Element, SubElement

from eidas_node.constants import LevelOfAssurance, NameIdFormat, ServiceProviderType, StatusCode, SubStatusCode
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.models import (
    LightRequest,
    LightResponse,
    LightToken,
    Status,
    deserialize_attributes,
    serialize_attributes,
)
from eidas_node.xml import dump_xml, parse_xml

DATA_DIR: Path = Path(__file__).parent / "data"

LIGHT_REQUEST_DICT = OrderedDict(
    [
        ("citizen_country_code", "CA"),
        ("id", "test-light-request-id"),
        ("issuer", "test-light-request-issuer"),
        ("level_of_assurance", LevelOfAssurance.LOW),
        ("name_id_format", NameIdFormat.UNSPECIFIED),
        ("provider_name", "DEMO-SP-CA"),
        ("sp_type", ServiceProviderType.PUBLIC),
        ("relay_state", "relay123"),
        ("sp_country_code", "CA"),
        (
            "requested_attributes",
            OrderedDict(
                [
                    ("http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier", []),
                    ("http://eidas.europa.eu/attributes/legalperson/EORI", []),
                    ("http://eidas.europa.eu/attributes/legalperson/LEI", []),
                    ("http://eidas.europa.eu/attributes/legalperson/LegalName", []),
                    ("http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress", []),
                    ("http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier", []),
                    ("http://eidas.europa.eu/attributes/legalperson/SEED", []),
                    ("http://eidas.europa.eu/attributes/legalperson/SIC", []),
                    ("http://eidas.europa.eu/attributes/legalperson/TaxReference", []),
                    ("http://eidas.europa.eu/attributes/legalperson/VATRegistrationNumber", []),
                    ("http://eidas.europa.eu/attributes/naturalperson/BirthName", []),
                    (
                        "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
                        [
                            "\n        PEFkZHJlc3NJZD5odHRwOi8vYWRkcmVzcy5leGFtcGxlL2lkL2JlL2VoMTFhYTwvQWRkcmVzc0lk\n"
                            "        Pg0KPFBvQm94PjEyMzQ8L1BvQm94ID4NCjxMb2NhdG9yRGVzaWduYXRvcj4yODwvTG9jYXRvckRlc2lnbmF\n"
                            "        0b3I+DQo8TG9jYXRvck5hbWU+RElHSVQgYnVpbGRpbmc8L0xvY2F0b3JOYW1lPg0KPEN2QWRkcmVzc0FyZW\n"
                            "        E+RXR0ZXJiZWVrPC9DdkFkZHJlc3NBcmVhPg0KPFRob3JvdWdoZmFyZT5SdWUgQmVsbGlhcmQ8L1Rob3Jvd\n"
                            "        WdoZmFyZT4NCjxQb3N0TmFtZT5FVFRFUkJFRUsgQ0hBU1NFPC9Qb3N0TmFtZT4NCjxBZG1pblVuaXRGaXJz\n"
                            "        dExpbmU+QkU8L0FkbWluVW5pdEZpcnN0TGluZT4NCjxBZG1pblVuaXRTZWNvbmRMaW5lPkVUVEVSQkVFSzw\n"
                            "        vQWRtaW5Vbml0U2Vjb25kTGluZT4NCjxQb3N0Q29kZT4xMDQwPC9Qb3N0Q29kZT4NCjxGdWxsQ3ZhZGRyZX\n"
                            "        NzPlJ1ZSBCZWxsaWFyZCAyOFxuQkUtMTA0MCBFdHRlcmJlZWs8L0Z1bGxDdmFkZHJlc3M+\n      "
                        ],
                    ),
                    ("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", []),
                    (
                        "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                        ["Antonio", "Lucio", "Vivaldi"],
                    ),
                    ("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth", []),
                    ("http://eidas.europa.eu/attributes/naturalperson/Gender", []),
                    ("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", ["Vivaldi-987654321"]),
                    ("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth", []),
                    ("http://eidas.europa.eu/attributes/legalperson/LegalAdditionalAttribute", []),
                    ("http://eidas.europa.eu/attributes/naturalperson/AdditionalAttribute", []),
                ]
            ),
        ),
        ("requester_id", None),
    ]
)

LIGHT_RESPONSE_DICT: Dict[str, Any] = OrderedDict(
    [
        ("id", "test-light-response-id"),
        ("in_response_to_id", "test-light-request-id"),
        ("issuer", "test-light-response-issuer"),
        ("ip_address", "127.0.0.1"),
        ("relay_state", "relay123"),
        ("subject", "CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9"),
        ("subject_name_id_format", NameIdFormat.PERSISTENT),
        ("level_of_assurance", LevelOfAssurance.LOW),
        (
            "status",
            OrderedDict(
                [
                    ("failure", False),
                    ("status_code", StatusCode.SUCCESS),
                    ("sub_status_code", None),
                    ("status_message", None),
                ]
            ),
        ),
        (
            "attributes",
            OrderedDict(
                [
                    ("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", ["ČERNÝCH"]),
                    ("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName", ["PAVEL"]),
                    ("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth", ["1956-07-15"]),
                    ("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth", ["Praha 2"]),
                    (
                        "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
                        [
                            "PGVpZGFzOkxvY2F0b3JEZXNpZ25hdG9yPjEwPC9laWRhczpMb2NhdG9yRGVzaWduYXRvcj4NCjxlaWRhczpUaG9yb3VnaGZhcm"
                            "U+WmEgcGlsb3U8L2VpZGFzOlRob3JvdWdoZmFyZT4NCjxlaWRhczpQb3N0TmFtZT7EjGVza8OhIEthbWVuaWNlPC9laWRhczpQ"
                            "b3N0TmFtZT4NCjxlaWRhczpQb3N0Q29kZT40MDcyMTwvZWlkYXM6UG9zdENvZGU+DQo8ZWlkYXM6Q3ZhZGRyZXNzQXJlYT7EjG"
                            "Vza8OhIEthbWVuaWNlLCBEb2xuw60gS2FtZW5pY2U8L2VpZGFzOkN2YWRkcmVzc0FyZWE+DQo="
                        ],
                    ),
                    (
                        "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                        ["CZ/CZ/ff70c9dd-6a05-4068-aaa2-b57be4f328e9"],
                    ),
                ]
            ),
        ),
        ("consent", None),
    ]
)

FAILED_LIGHT_RESPONSE_DICT: Dict[str, Any] = OrderedDict(
    [
        ("id", "test-light-response-id"),
        ("in_response_to_id", "test-light-request-id"),
        ("issuer", "test-light-response-issuer"),
        ("ip_address", None),
        ("relay_state", "relay123"),
        ("subject", None),
        ("subject_name_id_format", None),
        ("level_of_assurance", None),
        (
            "status",
            OrderedDict(
                [
                    ("failure", True),
                    ("status_code", StatusCode.REQUESTER),
                    ("sub_status_code", SubStatusCode.REQUEST_DENIED),
                    ("status_message", "Something went wrong."),
                ]
            ),
        ),
        ("attributes", OrderedDict()),
        ("consent", None),
    ]
)


class ValidationMixin:
    # Model to validate
    MODEL: type
    # Optional fields - can be None
    OPTIONAL: Set[str] = set()
    # Example of valid data
    VALID_DATA: Dict[str, Any]
    # Invalid data for basic type checks. Extra checks must have own test method.
    INVALID_DATA: Dict[str, Any]

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
                    with cast(SimpleTestCase, self).assertRaises(ValidationError):
                        self.MODEL(**data).validate()
                else:
                    self.MODEL(**self.VALID_DATA).validate()

    def test_invalid(self):
        t = cast(SimpleTestCase, self)
        for name in self.INVALID_DATA:
            with t.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] = self.INVALID_DATA[name]
                t.assertRaises(ValidationError, self.MODEL(**data).validate)

    def assert_attributes_valid(self, field_name: str) -> None:
        t = cast(SimpleTestCase, self)
        invalid_attributes: tuple = (
            {b"attr1": []},
            {"attr1": None},
            {"attr1": [None]},
            {"attr1": ["value1", None]},
        )
        data = self.VALID_DATA.copy()
        for i, invalid in enumerate(invalid_attributes):
            with t.subTest(i=i):
                data[field_name] = invalid
                t.assertRaises(ValidationError, self.MODEL(**data).validate)


class TestLightToken(ValidationMixin, SimpleTestCase):
    MODEL = LightToken
    VALID_DATA = {
        "id": "852a64c0-8ac1-445f-b0e1-992ada493033",
        "issuer": "specificCommunicationDefinitionConnectorRequest",
        "created": datetime(2017, 12, 11, 14, 12, 5, 148000),
    }
    INVALID_DATA = {
        "id": 123,
        "issuer": b"specificCommunicationDefinitionConnectorRequest",
        "created": "2017-12-11 14:12:05 148",
    }
    SECRET = "mySecretConnectorRequest"
    ENCODED_TOKEN = (
        b"c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0"
        b"0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk"
        b"lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWUU9"
    )

    def get_token(self, **kwargs) -> LightToken:
        data = self.VALID_DATA.copy()
        data.update(**kwargs)
        return LightToken(**data)

    def test_pipe_character_not_allowed(self):
        for name in "id", "issuer":
            with self.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] = str(data[name]) + "|pipe"
                self.assertRaises(ValidationError, self.MODEL(**data).validate)

    def test_digest(self):
        token = self.get_token()
        digest = token.digest("sha256", self.SECRET)
        expected_digest = b64decode(b"7M8p+uP8CKXuMi2IqSda1tg452WlRvcOSwu0dcisSYE=")
        self.assertEqual(expected_digest, digest)

    def test_encode(self):
        token = self.get_token()
        self.assertEqual(token.encode("sha256", self.SECRET), self.ENCODED_TOKEN)

    def test_decode_ok(self):
        self.assertEqual(LightToken.decode(self.ENCODED_TOKEN, "sha256", self.SECRET), self.get_token())

    def test_decode_validation_error(self):
        with mock.patch.object(LightToken, "validate"):
            encoded = self.get_token(issuer="").encode("sha256", self.SECRET)

        with self.assertRaisesMessage(ValidationError, "Must be str, not NoneType"):
            LightToken.decode(encoded, "sha256", self.SECRET)

    def test_decode_max_size_exceeded(self):
        with self.assertRaisesMessage(ParseError, "Maximal token size exceeded."):
            LightToken.decode(self.ENCODED_TOKEN * 100, "sha256", self.SECRET)

    def test_decode_wrong_number_of_parts(self):
        token = self.get_token(issuer="specificCommunicationDefinitionConnectorRequest|extra")
        with mock.patch.object(LightToken, "validate"):
            encoded = token.encode("sha256", self.SECRET)

        with self.assertRaisesMessage(ParseError, "wrong number of parts"):
            LightToken.decode(encoded, "sha256", self.SECRET)

    def test_decode_wrong_secret(self):
        with self.assertRaisesMessage(SecurityError, "invalid digest"):
            LightToken.decode(self.ENCODED_TOKEN, "sha256", "Dycky Most!")

    def test_decode_wrong_digest(self):
        encoded = (
            b"c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0"
            b"0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk"
            b"lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWWs9"
        )
        with self.assertRaisesMessage(SecurityError, "invalid digest"):
            LightToken.decode(encoded, "sha256", self.SECRET)


class TestLightRequest(ValidationMixin, SimpleTestCase):
    MODEL = LightRequest
    OPTIONAL = {"issuer", "name_id_format", "provider_name", "sp_type", "relay_state", "sp_country_code"}
    VALID_DATA = {
        "citizen_country_code": "CZ",
        "sp_country_code": "CZ",
        "id": "uuid",
        "issuer": "MyIssuer",
        "level_of_assurance": LevelOfAssurance.LOW,
        "name_id_format": NameIdFormat.PERSISTENT,
        "provider_name": "MyProvider",
        "sp_type": ServiceProviderType.PUBLIC,
        "relay_state": "state 123",
        "requested_attributes": {"attr1": [], "attr2": ["value1", "value2"]},
    }
    INVALID_DATA = {
        "citizen_country_code": 1,
        "sp_country_code": 1,
        "id": 1,
        "issuer": 1,
        "level_of_assurance": LevelOfAssurance.LOW.value,
        "name_id_format": NameIdFormat.PERSISTENT.value,
        "provider_name": 1,
        "sp_type": ServiceProviderType.PUBLIC.value,
        "relay_state": 1,
        "requested_attributes": ["attr1"],
    }

    def test_attributes(self):
        self.assert_attributes_valid("requested_attributes")

    def test_load_xml_full_sample(self):
        with cast(BinaryIO, (DATA_DIR / "light_request.xml").open("rb")) as f:
            request = LightRequest.load_xml(parse_xml(f))
        self.assertEqual(request, LightRequest(**LIGHT_REQUEST_DICT))

    def test_load_xml_minimal_sample(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / "light_request_minimal.xml").open("rb")) as f:
            request = LightRequest.load_xml(parse_xml(f))

        self.assertEqual(request.citizen_country_code, "CA")
        self.assertEqual(request.id, "test-light-request-id")
        self.assertIsNone(request.issuer)
        self.assertEqual(request.level_of_assurance, LevelOfAssurance.LOW)
        self.assertIsNone(request.name_id_format)
        self.assertIsNone(request.provider_name)
        self.assertIsNone(request.sp_type)
        self.assertIsNone(request.relay_state)
        self.assertEqual(request.requested_attributes, {})

    def test_load_xml_wrong_root_element(self):
        data = parse_xml(b"<lightResponse></lightResponse>")
        with self.assertRaisesMessage(ValidationError, "'<lightResponse>': \"Invalid root element 'lightResponse'.\""):
            LightRequest.load_xml(data)

    def test_load_xml_unknown_element(self):
        data = parse_xml(b"<lightRequest><myField>data</myField></lightRequest>")
        with self.assertRaisesMessage(ValidationError, "'<lightRequest><myField>': \"Unknown element 'myField'.\""):
            LightRequest.load_xml(data)

    def test_load_xml_attributes_unexpected_element(self):
        data = parse_xml(
            b"<lightRequest><requestedAttributes><myField>data</myField></requestedAttributes></lightRequest>"
        )
        with self.assertRaisesMessage(
            ValidationError, "'<lightRequest><requestedAttributes><myField>': \"Unexpected element 'myField'\""
        ):
            LightRequest.load_xml(data)

    def test_load_xml_attributes_definition_element(self):
        data = parse_xml(
            b"<lightRequest><requestedAttributes><attribute>data</attribute></requestedAttributes></lightRequest>"
        )
        with self.assertRaisesMessage(
            ValidationError, "'<lightRequest><requestedAttributes><attribute>': 'Missing attribute.definition element.'"
        ):
            LightRequest.load_xml(data)
        data = parse_xml(
            b"<lightRequest><requestedAttributes><attribute><foo>data</foo>"
            b"</attribute></requestedAttributes></lightRequest>"
        )
        with self.assertRaisesMessage(
            ValidationError, "'<lightRequest><requestedAttributes><attribute><foo>': \"Unexpected element 'foo'\""
        ):
            LightRequest.load_xml(data)

    def test_load_xml_attribute_values_unexpected_element(self):
        data = parse_xml(
            b"<lightRequest><requestedAttributes><attribute><definition>data</definition><foo/>"
            b"</attribute></requestedAttributes></lightRequest>"
        )
        with self.assertRaisesMessage(
            ValidationError, "'<lightRequest><requestedAttributes><attribute><foo>': \"Unexpected element 'foo'\""
        ):
            LightRequest.load_xml(data)

    def test_export_xml_full_sample(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / "light_request.xml").open("rb")) as f:
            data = f.read()
            request = LightRequest.load_xml(parse_xml(data))
        self.assertEqual(dump_xml(request.export_xml()), data)

    def test_export_xml_minimal_sample(self):
        request = LightRequest(
            citizen_country_code="CA",
            id="test-light-request-id",
            level_of_assurance=LevelOfAssurance.LOW,
            requested_attributes={},
        )
        with cast(BinaryIO, (DATA_DIR / "light_request_minimal.xml").open("rb")) as f:
            data = f.read()
        self.assertEqual(dump_xml(request.export_xml()), data)


class TestStatus(ValidationMixin, SimpleTestCase):
    MODEL = Status
    OPTIONAL = {"failure", "status_code", "sub_status_code", "status_message"}
    VALID_DATA = {
        "failure": True,
        "status_code": StatusCode.REQUESTER,
        "sub_status_code": SubStatusCode.REQUEST_DENIED,
        "status_message": "Oops.",
    }
    INVALID_DATA = {
        "failure": 1,
        "status_code": str(StatusCode.REQUESTER),
        "sub_status_code": str(SubStatusCode.REQUEST_DENIED),
        "status_message": 1,
    }

    def test_deserialize_sub_status_code_invalid(self):
        status = Status()
        elm = Element("subStatusCode")
        for invalid in "##", "test ## test":
            elm.text = invalid
            self.assertIsNone(status.deserialize_sub_status_code(elm))


class TestLightResponse(ValidationMixin, SimpleTestCase):
    MODEL = LightResponse
    OPTIONAL = {"issuer", "ip_address", "relay_state"}
    OPTIONAL_FAILURE = {
        "issuer",
        "ip_address",
        "relay_state",
        "subject",
        "subject_name_id_format",
        "level_of_assurance",
    }
    VALID_DATA = {
        "id": "uuid",
        "in_response_to_id": "uuid2",
        "issuer": "MyIssuer",
        "ip_address": "127.0.0.1",
        "relay_state": "state 123",
        "subject": "my subject",
        "subject_name_id_format": NameIdFormat.PERSISTENT,
        "level_of_assurance": LevelOfAssurance.LOW,
        "status": Status(failure=False),
        "attributes": OrderedDict(
            [
                ("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", []),
                ("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName", ["Antonio", "Lucio"]),
            ]
        ),
    }
    INVALID_DATA = {
        "id": 1,
        "in_response_to_id": 2,
        "issuer": 3,
        "ip_address": 4,
        "relay_state": 5,
        "subject": 6,
        "subject_name_id_format": str(NameIdFormat.PERSISTENT),
        "level_of_assurance": str(LevelOfAssurance.LOW),
        "attributes": ["attr1"],
    }

    def tearDown(self) -> None:
        if self.VALID_DATA is not self.__class__.VALID_DATA:
            del self.VALID_DATA
        if self.OPTIONAL is not self.__class__.OPTIONAL:
            del self.OPTIONAL

    def create_response(self, success: bool) -> LightResponse:
        data = (LIGHT_RESPONSE_DICT if success else FAILED_LIGHT_RESPONSE_DICT).copy()
        data["status"] = Status(**data["status"])
        return LightResponse(**data)

    def set_failure(self, failure: bool) -> None:
        data = self.__class__.VALID_DATA.copy()
        if failure:
            self.OPTIONAL = self.__class__.OPTIONAL_FAILURE
            data.update(
                {
                    "status": Status(
                        failure=failure,
                        status_code=StatusCode.REQUESTER,
                        sub_status_code=SubStatusCode.REQUEST_DENIED,
                        status_message="Oops.",
                    ),
                    "attributes": OrderedDict(),
                    "subject": None,
                    "subject_name_id_format": None,
                    "level_of_assurance": None,
                }
            )
        else:
            self.OPTIONAL = self.__class__.OPTIONAL
            data["status"] = Status(failure=False)
        self.VALID_DATA = data

    def test_required_for_failure(self):
        self.set_failure(True)
        self.test_required()

    def test_attributes_with_response_status_ok(self):
        self.set_failure(False)
        self.assert_attributes_valid("attributes")

    def test_attributes_with_response_status_failure(self):
        self.set_failure(True)
        self.assert_attributes_valid("attributes")

    def test_export_xml_with_response_status_ok(self):
        self.maxDiff = None
        response = self.create_response(True)
        with cast(BinaryIO, (DATA_DIR / "light_response.xml").open("r")) as f:
            data = f.read()
        self.assertEqual(dump_xml(response.export_xml()).decode("utf-8"), data)

    def test_export_xml_with_response_status_failure(self):
        self.maxDiff = None
        response = self.create_response(False)
        with cast(BinaryIO, (DATA_DIR / "light_response_failure.xml").open("r")) as f:
            data = f.read()
        self.assertEqual(dump_xml(response.export_xml()).decode("utf-8"), data)

    def test_load_xml_with_response_status_ok(self):
        self.maxDiff = None
        self.set_failure(False)
        response = self.create_response(True)
        with cast(BinaryIO, (DATA_DIR / "light_response.xml").open("r")) as f:
            data = f.read()
        self.assertEqual(LightResponse.load_xml(parse_xml(data)), response)

    def test_load_xml_with_response_status_failure(self):
        self.maxDiff = None
        response = self.create_response(False)
        with cast(BinaryIO, (DATA_DIR / "light_response_failure.xml").open("r")) as f:
            data = f.read()

        self.assertEqual(LightResponse.load_xml(parse_xml(data)), response)


class TestDeserializeAttributes(SimpleTestCase):
    def test_deserialize_attributes_ok(self):
        root = Element("whatever")
        attribute = SubElement(root, "attribute")
        SubElement(attribute, "definition").text = "name1"
        SubElement(attribute, "value").text = "value1"
        SubElement(attribute, "value").text = "value2"
        attribute = SubElement(root, "attribute")
        SubElement(attribute, "definition").text = "name2"
        self.assertDictEqual(
            deserialize_attributes(root),
            {
                "name1": ["value1", "value2"],
                "name2": [],
            },
        )

    def test_deserialize_attributes_empty(self):
        root = Element("whatever")
        self.assertDictEqual(deserialize_attributes(root), {})

    def test_deserialize_attributes_unexpected_element_need_attribute(self):
        root = Element("whatever")
        SubElement(root, "myName").text = "name"
        with self.assertRaisesMessage(ValidationError, "'<whatever><myName>': \"Unexpected element 'myName'\""):
            deserialize_attributes(root)

    def test_deserialize_attributes_missing_definition_element(self):
        root = Element("whatever")
        SubElement(root, "attribute").text = "name"
        with self.assertRaisesMessage(
            ValidationError, "'<whatever><attribute>': 'Missing attribute.definition element.'"
        ):
            deserialize_attributes(root)

    def test_deserialize_attributes_unexpected_element_need_definition(self):
        root = Element("whatever")
        attribute = SubElement(root, "attribute")
        SubElement(attribute, "wrong").text = "element"
        with self.assertRaisesMessage(
            ValidationError, "'<whatever><attribute><wrong>': \"Unexpected element 'wrong'\""
        ):
            deserialize_attributes(root)

    def test_deserialize_attributes_values_unexpected_element(self):
        root = Element("whatever")
        attribute = SubElement(root, "attribute")
        SubElement(attribute, "definition").text = "name"
        SubElement(attribute, "wrong").text = "element"
        with self.assertRaisesMessage(
            ValidationError, "'<whatever><attribute><wrong>': \"Unexpected element 'wrong'\""
        ):
            deserialize_attributes(root)


class TestSerializeAttributes(SimpleTestCase):
    def test_serialize_attributes_none(self):
        root = Element("root")
        serialize_attributes(root, "tagName", None)
        expected = Element("root")
        self.assertEqual(dump_xml(root).decode("utf-8"), dump_xml(expected).decode("utf-8"))

    def test_serialize_attributes_empty(self):
        root = Element("root")
        serialize_attributes(root, "tagName", {})
        expected = Element("root")
        SubElement(expected, "tagName")
        self.assertEqual(dump_xml(root).decode("utf-8"), dump_xml(expected).decode("utf-8"))

    def test_serialize_attributes_not_empty(self):
        root = Element("root")
        serialize_attributes(
            root,
            "tagName",
            OrderedDict(
                [
                    ("name1", ["value1", "value2"]),
                    ("name2", []),
                ]
            ),
        )
        expected = Element("root")
        attributes = SubElement(expected, "tagName")
        attribute = SubElement(attributes, "attribute")
        SubElement(attribute, "definition").text = "name1"
        SubElement(attribute, "value").text = "value1"
        SubElement(attribute, "value").text = "value2"
        attribute = SubElement(attributes, "attribute")
        SubElement(attribute, "definition").text = "name2"
        self.assertEqual(dump_xml(root).decode("utf-8"), dump_xml(expected).decode("utf-8"))
