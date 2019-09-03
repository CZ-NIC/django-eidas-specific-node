from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, ContextManager, TextIO, cast

import xmlsec
from django.test import SimpleTestCase
from lxml.etree import Element, ElementTree, SubElement

from eidas_node.constants import LevelOfAssurance, StatusCode, SubStatusCode
from eidas_node.errors import ValidationError
from eidas_node.models import LightRequest, LightResponse, Status
from eidas_node.saml import NAMESPACES, Q_NAMES, SAMLRequest, SAMLResponse, create_eidas_attribute, decrypt_xml
from eidas_node.tests.test_models import FAILED_LIGHT_RESPONSE_DICT, LIGHT_REQUEST_DICT, LIGHT_RESPONSE_DICT
from eidas_node.utils import dump_xml, parse_xml

DATA_DIR = Path(__file__).parent / 'data'  # type: Path

LIGHT_RESPONSE_DICT = LIGHT_RESPONSE_DICT.copy()
FAILED_LIGHT_RESPONSE_DICT = FAILED_LIGHT_RESPONSE_DICT.copy()
OVERRIDES = {
    'id': 'test-saml-response-id',
    'in_response_to_id': 'Ttest-saml-request-id',
    'issuer': 'test-saml-response-issuer',
}
LIGHT_RESPONSE_DICT.update(OVERRIDES)
LIGHT_RESPONSE_DICT['level_of_assurance'] = LevelOfAssurance.LOW
FAILED_LIGHT_RESPONSE_DICT.update(OVERRIDES)

LIGHT_REQUEST_DICT = LIGHT_REQUEST_DICT.copy()
LIGHT_REQUEST_DICT.update({'id': 'test-saml-request-id', 'issuer':  'test-saml-request-issuer'})


class ValidationErrorMixin:
    def assert_validation_error(self, path: str, message: str, *args, **kwargs) -> ContextManager[None]:
        message = str(dict([(path, message)]))
        return cast(SimpleTestCase, self).assertRaisesMessage(ValidationError, message, *args, **kwargs)


class TestDecrypt(SimpleTestCase):
    KEY_FILE = str(DATA_DIR / 'key.pem')
    WRONG_KEY_FILE = str(DATA_DIR / 'wrong-key.pem')

    def test_decrypt_xml_with_document_not_encrypted(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            document = parse_xml(f.read())
        expected = dump_xml(document).decode('utf-8')
        decrypt_xml(document, self.KEY_FILE)
        actual = dump_xml(document).decode('utf-8')
        self.assertXMLEqual(expected, actual)

    def test_decrypt_xml_with_document_encrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_decrypted.xml').open('rb')) as f:
            document_decrypted = parse_xml(f.read())
        with cast(BinaryIO, (DATA_DIR / 'saml_response_encrypted.xml').open('rb')) as f:
            document_encrypted = parse_xml(f.read())
        expected = dump_xml(document_decrypted).decode('utf-8')
        decrypt_xml(document_encrypted, self.KEY_FILE)
        actual = dump_xml(document_encrypted).decode('utf-8')
        self.assertXMLEqual(expected, actual)

    def test_decrypt_xml_with_document_encrypted_wrong_key(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_encrypted.xml').open('rb')) as f:
            document_encrypted = parse_xml(f.read())
        self.assertRaises(xmlsec.Error, decrypt_xml, document_encrypted, self.WRONG_KEY_FILE)

    def test_decrypt_xml_with_document_decrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_decrypted.xml').open('rb')) as f:
            document_decrypted = parse_xml(f.read())
        expected = dump_xml(document_decrypted).decode('utf-8')
        decrypt_xml(document_decrypted, self.KEY_FILE)
        actual = dump_xml(document_decrypted).decode('utf-8')
        self.assertXMLEqual(expected, actual)


class TestSAMLRequest(ValidationErrorMixin, SimpleTestCase):
    def test_from_light_request(self):
        self.maxDiff = None
        saml_request = SAMLRequest.from_light_request(
            LightRequest(**LIGHT_REQUEST_DICT), 'test/destination', datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_request.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_request.document).decode('utf-8'), data)
        self.assertEqual(saml_request.relay_state, 'relay123')
        self.assertEqual(saml_request.citizen_country_code, 'CA')

    def test_from_light_request_minimal(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / 'light_request_minimal.xml').open('rb')) as f:
            request = LightRequest.load_xml(parse_xml(f))
        request.id = 'test-saml-request-id'

        saml_request = SAMLRequest.from_light_request(
            request, 'test/destination', datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_request_minimal.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_request.document).decode('utf-8'), data)
        self.assertEqual(saml_request.relay_state, None)
        self.assertEqual(saml_request.citizen_country_code, 'CA')

    def test_from_light_request_invalid_id(self):
        self.maxDiff = None

        with cast(BinaryIO, (DATA_DIR / 'light_request_minimal.xml').open('rb')) as f:
            request = LightRequest.load_xml(parse_xml(f))
        request.id = '0day'

        with self.assert_validation_error('id', "Light request id is not a valid XML id: '0day'"):
            SAMLRequest.from_light_request(request, 'test/destination', datetime(2017, 12, 11, 14, 12, 5, 148000))

    def test_create_light_request_success(self):
        self.maxDiff = None
        with cast(TextIO, (DATA_DIR / 'saml_request.xml').open('r')) as f:
            data = f.read()

        saml_request = SAMLRequest(parse_xml(data), 'CA', 'relay123')
        self.assertEqual(
            saml_request.create_light_request().get_data_as_dict(), LIGHT_REQUEST_DICT)

    def test_create_light_request_extra_elements(self):
        self.maxDiff = None
        with cast(TextIO, (DATA_DIR / 'saml_request.xml').open('r')) as f:
            document = parse_xml(f.read())

        SubElement(document.getroot(), 'extra').text = 'extra'
        SubElement(document.find(".//{}".format(Q_NAMES['eidas:RequestedAttributes'])), 'extra').text = 'extra'

        saml_request = SAMLRequest(document, 'CA', 'relay123')
        self.assertEqual(
            saml_request.create_light_request().get_data_as_dict(), LIGHT_REQUEST_DICT)

    def test_create_light_request_invalid_root_element(self):
        root = Element('wrongRoot')
        saml_request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assert_validation_error(
            '<wrongRoot>', "Wrong root element: 'wrongRoot'",
            saml_request.create_light_request)

    def test_create_light_request_missing_attribute_name(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=NAMESPACES)
        extensions = SubElement(root, Q_NAMES['saml2p:Extensions'])
        attributes = SubElement(extensions, Q_NAMES['eidas:RequestedAttributes'])
        SubElement(attributes, Q_NAMES['eidas:RequestedAttribute'])

        saml_request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assert_validation_error(
            '<saml2p:AuthnRequest><saml2p:Extensions><eidas:RequestedAttributes><eidas:RequestedAttribute>',
            "Missing attribute 'Name'",
            saml_request.create_light_request)

    def test_create_light_request_without_extensions(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=NAMESPACES)
        saml_request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        expected = LightRequest(citizen_country_code='CZ', relay_state='relay123', requested_attributes=OrderedDict())
        self.assertEqual(saml_request.create_light_request(), expected)

    def test_str(self):
        self.assertEqual(
            str(SAMLRequest(ElementTree(Element('root')), 'CZ', 'relay')),
            "citizen_country_code = 'CZ', relay_state = 'relay', document = "
            "<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<root/>\n")
        self.assertEqual(str(SAMLRequest(None, None, None)),
                         'citizen_country_code = None, relay_state = None, document = None')


class TestSAMLResponse(ValidationErrorMixin, SimpleTestCase):
    def create_light_response(self, success: bool, **kwargs) -> LightResponse:
        data = (LIGHT_RESPONSE_DICT if success else FAILED_LIGHT_RESPONSE_DICT).copy()
        data['status'] = Status(**data['status'])
        data.update(**kwargs)
        return LightResponse(**data)

    def test_create_light_response_not_encrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            saml_response = SAMLResponse(parse_xml(f), 'relay123')

        light_response = saml_response.create_light_response()
        self.assertEqual(light_response, self.create_light_response(True))

    def test_create_light_response_decrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_decrypted.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f), 'relay123')
        light_response = self.create_light_response(
            True,
            level_of_assurance=LevelOfAssurance.SUBSTANTIAL,
            ip_address='217.31.205.1',
            id='_751e557772344aa59e9e3f35d2c9f6d6',
            in_response_to_id='e399fb9b-9454-4284-831f-4aa33d83757e',
            issuer='urn:microsoft:cgg2010:fpsts'
        )
        self.assertEqual(response.create_light_response(), light_response)

    def test_create_light_response_not_decrypted(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response_encrypted.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f))
        self.assert_validation_error(
            '<samlp:Response><saml:EncryptedAssertion><xenc:EncryptedData>',
            "Unexpected element: '{http://www.w3.org/2001/04/xmlenc#}EncryptedData'.",
            response.create_light_response)

    def test_create_light_response_wrong_root_element(self):
        root = Element('wrongRoot')
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<wrongRoot>', "Wrong root element: 'wrongRoot'",
            saml_response.create_light_response)

    def test_create_light_response_missing_decrypted_assertion(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<saml2p:Response><saml2:EncryptedAssertion>',
            'Missing assertion element.',
            saml_response.create_light_response)

    def test_create_light_response_decrypted_assertion_unexpected_element(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        SubElement(SubElement(root, Q_NAMES['saml2:EncryptedAssertion']), 'wrong')
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<saml2p:Response><saml2:EncryptedAssertion><wrong>',
            "Unexpected element: 'wrong'.",
            saml_response.create_light_response)

    def test_create_light_response_attribute_unexpected_element(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        SubElement(SubElement(assertion, Q_NAMES['saml2:AttributeStatement']), 'wrong')
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<saml2p:Response><saml2:Assertion><saml2:AttributeStatement><wrong>',
            "Unexpected element: 'wrong'.",
            saml_response.create_light_response)

    def test_create_light_response_attribute_value_unexpected_element(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        attributes = SubElement(assertion, Q_NAMES['saml2:AttributeStatement'])
        SubElement(SubElement(attributes, Q_NAMES['saml2:Attribute']), 'wrong')
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<saml2p:Response><saml2:Assertion><saml2:AttributeStatement><saml2:Attribute><wrong>',
            "Unexpected element: 'wrong'.",
            saml_response.create_light_response)

    def test_create_light_response_failed_response(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_failed.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f), 'relay123')
        self.assertEqual(response.create_light_response(), self.create_light_response(False))

    def test_create_light_response_with_extra_elements(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f), 'relay123')
        SubElement(response.document.find(".//{}".format(Q_NAMES['saml2p:StatusCode'])), 'something')
        SubElement(response.document.find(".//{}".format(Q_NAMES['saml2:AuthnStatement'])), 'something')
        SubElement(response.document.find(".//{}".format(Q_NAMES['saml2:AuthnContext'])), 'something')
        self.assertEqual(response.create_light_response(), self.create_light_response(True))

    def test_create_light_response_with_status_version_mismatch(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response_failed_version_mismatch.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f), 'relay123')

        expected = self.create_light_response(False)
        expected.status.status_code = StatusCode.REQUESTER
        expected.status.sub_status_code = SubStatusCode.VERSION_MISMATCH
        self.assertEqual(response.create_light_response(), expected)

    def test_create_light_response_with_unsupported_sub_status(self):
        with cast(BinaryIO, (DATA_DIR / 'saml_response_failed_unsupported_sub_status.xml').open('rb')) as f:
            response = SAMLResponse(parse_xml(f), 'relay123')

        expected = self.create_light_response(False)
        expected.status.sub_status_code = None
        self.assertEqual(response.create_light_response(), expected)

    def test_str(self):
        self.assertEqual(
            str(SAMLResponse(ElementTree(Element('root')), 'relay')),
            "relay_state = 'relay', document = <?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<root/>\n")
        self.assertEqual(str(SAMLResponse(None, None)), 'relay_state = None, document = None')


class TestCreateEidasAttribute(SimpleTestCase):
    def test_create_eidas_attribute_known_attribute(self):
        root = Element('whatever')
        elm = create_eidas_attribute(root, 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', True)
        self.assertIs(elm, root[0])
        expected = Element('whatever')
        SubElement(expected, Q_NAMES['eidas:RequestedAttribute'], {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
            'FriendlyName': 'FamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'isRequired': 'true',
        })
        self.assertXMLEqual(dump_xml(root).decode('utf-8'), dump_xml(expected).decode('utf-8'))

    def test_create_eidas_attribute_unknown_attribute(self):
        root = Element('whatever')
        elm = create_eidas_attribute(root, 'http://eidas.europa.eu/attributes/naturalperson/ConcurrentFamilyName', True)
        self.assertIs(elm, root[0])
        expected = Element('whatever')
        SubElement(expected, Q_NAMES['eidas:RequestedAttribute'], {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/ConcurrentFamilyName',
            'FriendlyName': 'ConcurrentFamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'isRequired': 'true',
        })
        self.assertXMLEqual(dump_xml(root).decode('utf-8'), dump_xml(expected).decode('utf-8'))
