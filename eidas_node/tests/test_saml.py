from collections import OrderedDict
from datetime import datetime
from typing import Any, BinaryIO, TextIO, cast
from unittest.mock import call, patch

from django.test import SimpleTestCase
from lxml.etree import Element, ElementTree, SubElement

from eidas_node.constants import LevelOfAssurance, StatusCode, SubStatusCode
from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.models import LightRequest, LightResponse, Status
from eidas_node.saml import EIDAS_NAMESPACES, Q_NAMES, SAMLRequest, SAMLResponse, create_attribute_elm_attributes
from eidas_node.tests.constants import CERT_FILE, DATA_DIR, KEY_FILE, NIA_CERT_FILE, SIGNATURE_OPTIONS
from eidas_node.tests.test_models import FAILED_LIGHT_RESPONSE_DICT, LIGHT_REQUEST_DICT, LIGHT_RESPONSE_DICT
from eidas_node.xml import SignatureInfo, dump_xml, parse_xml, remove_extra_xml_whitespace

LIGHT_RESPONSE_DICT = LIGHT_RESPONSE_DICT.copy()
FAILED_LIGHT_RESPONSE_DICT = FAILED_LIGHT_RESPONSE_DICT.copy()
OVERRIDES = {
    'id': 'test-saml-response-id',
    'in_response_to_id': 'test-saml-request-id',
    'issuer': 'test-saml-response-issuer',
}
LIGHT_RESPONSE_DICT.update(OVERRIDES)
LIGHT_RESPONSE_DICT['level_of_assurance'] = LevelOfAssurance.LOW
FAILED_LIGHT_RESPONSE_DICT.update(OVERRIDES)

LIGHT_REQUEST_DICT = LIGHT_REQUEST_DICT.copy()
LIGHT_REQUEST_DICT.update({'id': 'test-saml-request-id', 'issuer':  'test-saml-request-issuer'})


class ValidationErrorMixin:
    def assert_validation_error(self, path: str, message: str, *args, **kwargs) -> Any:
        message = str(dict([(path, message)]))
        return cast(SimpleTestCase, self).assertRaisesMessage(ValidationError, message, *args, **kwargs)


class TestSAMLRequest(ValidationErrorMixin, SimpleTestCase):
    def test_id(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], {'ID': 'test-id'}, nsmap=EIDAS_NAMESPACES)
        request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assertEqual(request.id, 'test-id')

    def test_id_none(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=EIDAS_NAMESPACES)
        request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assertIsNone(request.id)

    def test_issuer(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=EIDAS_NAMESPACES)
        SubElement(root, Q_NAMES['saml2:Issuer']).text = 'test-issuer'
        request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assertEqual(request.issuer, 'test-issuer')

    def test_issuer_none(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=EIDAS_NAMESPACES)
        request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assertIsNone(request.issuer)

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
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=EIDAS_NAMESPACES)
        extensions = SubElement(root, Q_NAMES['saml2p:Extensions'])
        attributes = SubElement(extensions, Q_NAMES['eidas:RequestedAttributes'])
        SubElement(attributes, Q_NAMES['eidas:RequestedAttribute'])

        saml_request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        self.assert_validation_error(
            '<saml2p:AuthnRequest><saml2p:Extensions><eidas:RequestedAttributes><eidas:RequestedAttribute>',
            "Missing attribute 'Name'",
            saml_request.create_light_request)

    def test_create_light_request_without_extensions(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'], nsmap=EIDAS_NAMESPACES)
        saml_request = SAMLRequest(ElementTree(root), 'CZ', 'relay123')
        expected = LightRequest(citizen_country_code='CZ', relay_state='relay123', requested_attributes=OrderedDict())
        self.assertEqual(saml_request.create_light_request(), expected)

    def test_request_signature_exists(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        # Booby trap
        SubElement(SubElement(root, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # This one must be found
        signature = SubElement(root, Q_NAMES['ds:Signature'])
        self.assertIs(SAMLRequest(ElementTree(root)).request_signature, signature)

    def test_request_signature_not_exists(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        # Booby trap
        SubElement(SubElement(root, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # No signature must be found
        self.assertIsNone(SAMLRequest(ElementTree(root)).request_signature)

    def test_sign_request(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        SubElement(root, Q_NAMES['saml2:Issuer'])
        request = SAMLRequest(ElementTree(root))
        request.sign_request(**SIGNATURE_OPTIONS)
        self.assertIsNotNone(request.request_signature)

    def test_sign_request_already_exists(self):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        signature = SubElement(root, Q_NAMES['ds:Signature'])
        SubElement(root, Q_NAMES['saml2:Issuer'])
        request = SAMLRequest(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'Request signature already exists.'):
            request.sign_request(**SIGNATURE_OPTIONS)
        self.assertIs(request.request_signature, signature)

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_request(self, signatures_mock):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        signature = SubElement(root, Q_NAMES['ds:Signature'])
        signatures_mock.return_value = [SignatureInfo(signature, (root,))]
        SAMLRequest(ElementTree(root)).verify_request('cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [call(root, 'cert.pem')])

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_request_none(self, signatures_mock):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        with self.assertRaisesMessage(SecurityError, 'Signature does not exist'):
            SAMLRequest(ElementTree(root)).verify_request('cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [])

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_request_not_found(self, signatures_mock):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        SubElement(root, Q_NAMES['ds:Signature'])
        signatures_mock.return_value = [SignatureInfo(Element(Q_NAMES['ds:Signature']), (root,))]
        with self.assertRaisesMessage(SecurityError, 'Signature not found'):
            SAMLRequest(ElementTree(root)).verify_request('cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [call(root, 'cert.pem')])

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_request_wrong_parent(self, signatures_mock):
        root = Element(Q_NAMES['saml2p:AuthnRequest'])
        signature = SubElement(root, Q_NAMES['ds:Signature'])
        signatures_mock.return_value = [SignatureInfo(signature, (Element('whatever'),))]
        with self.assertRaisesMessage(SecurityError, 'Signature does not reference parent element'):
            SAMLRequest(ElementTree(root)).verify_request('cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [call(root, 'cert.pem')])

    def test_str(self):
        self.assertEqual(
            str(SAMLRequest(ElementTree(Element('root')), 'CZ', 'relay')),
            "citizen_country_code = 'CZ', relay_state = 'relay', document = "
            "<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<root/>\n")
        self.assertEqual(str(SAMLRequest(None, None, None)),
                         'citizen_country_code = None, relay_state = None, document = None')


class TestSAMLResponse(ValidationErrorMixin, SimpleTestCase):
    def test_id(self):
        root = Element(Q_NAMES['saml2p:Response'], {'ID': 'test-id'}, nsmap=EIDAS_NAMESPACES)
        request = SAMLResponse(ElementTree(root))
        self.assertEqual(request.id, 'test-id')

    def test_id_none(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        request = SAMLResponse(ElementTree(root))
        self.assertIsNone(request.id)

    def test_in_response_to_id(self):
        root = Element(Q_NAMES['saml2p:Response'], {'InResponseTo': 'test-id'}, nsmap=EIDAS_NAMESPACES)
        response = SAMLResponse(ElementTree(root))
        self.assertEqual(response.in_response_to_id, 'test-id')

    def test_in_response_to_id_none(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        response = SAMLResponse(ElementTree(root))
        self.assertIsNone(response.in_response_to_id)

    def test_issuer(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        SubElement(root, Q_NAMES['saml2:Issuer']).text = 'test-issuer'
        response = SAMLResponse(ElementTree(root))
        self.assertEqual(response.issuer, 'test-issuer')

    def test_issuer_none(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        response = SAMLResponse(ElementTree(root))
        self.assertIsNone(response.issuer)

    def create_light_response(self, success: bool, **kwargs) -> LightResponse:
        data = (LIGHT_RESPONSE_DICT if success else FAILED_LIGHT_RESPONSE_DICT).copy()
        data['status'] = Status(**data['status'])
        data.update(**kwargs)
        return LightResponse(**data)

    def test_from_light_response(self):
        self.maxDiff = None
        saml_response = SAMLResponse.from_light_response(
            self.create_light_response(True), 'test/destination', datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_response_from_light_response.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), data)

    def test_from_light_response_minimal(self):
        self.maxDiff = None
        status = Status(failure=False)
        response = self.create_light_response(True, ip_address=None, status=status, attributes={})
        saml_response = SAMLResponse.from_light_response(
            response, None, datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_response_from_light_response_minimal.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), data)

    def test_from_light_response_failed(self):
        self.maxDiff = None
        status = Status(failure=True, sub_status_code=SubStatusCode.AUTHN_FAILED, status_message='Oops.')
        response = self.create_light_response(False, issuer=None, ip_address=None, status=status)
        saml_response = SAMLResponse.from_light_response(
            response, None, datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_response_from_light_response_failed.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), data)

    def test_from_light_response_version_mismatch(self):
        self.maxDiff = None
        status = Status(failure=True, sub_status_code=SubStatusCode.VERSION_MISMATCH, status_message='Oops.')
        response = self.create_light_response(False, issuer=None, ip_address=None, status=status)
        saml_response = SAMLResponse.from_light_response(
            response, None, datetime(2017, 12, 11, 14, 12, 5, 148000))

        with cast(TextIO, (DATA_DIR / 'saml_response_from_light_response_version_mismatch.xml').open('r')) as f2:
            data = f2.read()
        self.assertXMLEqual(dump_xml(saml_response.document).decode('utf-8'), data)

    def test_decrypt(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / 'saml_response_decrypted.xml').open('rb')) as f:
            document_decrypted = f.read()
        with cast(BinaryIO, (DATA_DIR / 'saml_response_encrypted.xml').open('rb')) as f:
            document_encrypted = f.read()

        response = SAMLResponse(parse_xml(document_encrypted))
        response.decrypt(KEY_FILE)
        self.assertXMLEqual(dump_xml(response.document).decode('utf-8'), document_decrypted.decode('utf-8'))

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
        self.assertEqual(response.create_light_response().attributes, {})

    def test_create_light_response_wrong_root_element(self):
        root = Element('wrongRoot')
        saml_response = SAMLResponse(ElementTree(root))
        self.assert_validation_error(
            '<wrongRoot>', "Wrong root element: 'wrongRoot'",
            saml_response.create_light_response)

    def test_create_light_response_missing_decrypted_assertion(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        saml_response = SAMLResponse(ElementTree(root))
        self.assertEqual(saml_response.create_light_response().attributes, {})

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

    def test_create_light_response_no_auth_statement(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        SubElement(root, Q_NAMES['saml2:Assertion'])
        saml = SAMLResponse(ElementTree(root))
        response = saml.create_light_response()
        self.assertIsNone(response.ip_address)
        self.assertIsNone(response.level_of_assurance)

    def test_create_light_response_empty_auth_statement(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=EIDAS_NAMESPACES)
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        SubElement(assertion, Q_NAMES['saml2:AuthnStatement'])
        saml = SAMLResponse(ElementTree(root))
        response = saml.create_light_response()
        self.assertIsNone(response.ip_address)
        self.assertIsNone(response.level_of_assurance)

    def test_create_light_response_unrecognized_auth_context_class(self):
        root = Element(Q_NAMES['saml2p:Response'], {'ID': 'id', 'InResponseTo': 'id0'}, nsmap=EIDAS_NAMESPACES)
        context_class = SubElement(SubElement(SubElement(SubElement(
            root, Q_NAMES['saml2:Assertion']), Q_NAMES['saml2:AuthnStatement']),
            Q_NAMES['saml2:AuthnContext']), Q_NAMES['saml2:AuthnContextClassRef'])
        context_class.text = 'saml2:AuthnContextClassRef:unrecognized'
        saml = SAMLResponse(ElementTree(root))
        response = saml.create_light_response()
        self.assertEqual(response.id, 'id')
        self.assertEqual(response.in_response_to_id, 'id0')
        self.assertTrue(response.status.failure)
        self.assertEqual(response.status.status_code, StatusCode.RESPONDER)
        self.assertIn('saml2:AuthnContextClassRef:unrecognized', response.status.status_message)
        self.assertIsNone(response.level_of_assurance)

    def test_str(self):
        self.assertEqual(
            str(SAMLResponse(ElementTree(Element('root')), 'relay')),
            "relay_state = 'relay', document = <?xml version='1.0' encoding='utf-8' standalone='yes'?>\n<root/>\n")
        self.assertEqual(str(SAMLResponse(None, None)), 'relay_state = None, document = None')

    def test_assertion_none(self):
        root = Element(Q_NAMES['saml2p:Response'])
        self.assertIsNone(SAMLResponse(ElementTree(root)).assertion)

    def test_assertion_exists(self):
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        self.assertIs(SAMLResponse(ElementTree(root)).assertion, assertion)

    def test_assertion_exists_decrypted(self):
        root = Element(Q_NAMES['saml2p:Response'])
        encrypted_assertion = SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        decrypted_assertion = SubElement(encrypted_assertion, Q_NAMES['saml2:Assertion'])
        self.assertIs(SAMLResponse(ElementTree(root)).assertion, decrypted_assertion)

    def test_assertion_too_many(self):
        root = Element(Q_NAMES['saml2p:Response'])
        SubElement(root, Q_NAMES['saml2:Assertion'])
        SubElement(SubElement(root, Q_NAMES['saml2:EncryptedAssertion']), Q_NAMES['saml2:Assertion'])
        with self.assertRaisesMessage(ParseError, 'Too many assertion elements'):
            SAMLResponse(ElementTree(root)).assertion

    def test_response_signature_not_exists(self):
        # Base structure
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        encrypted_assertion = SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        decrypted_assertion = SubElement(encrypted_assertion, Q_NAMES['saml2:Assertion'])
        # Place a few signature elements as booby traps
        SubElement(assertion, Q_NAMES['ds:Signature'])
        SubElement(decrypted_assertion, Q_NAMES['ds:Signature'])
        SubElement(SubElement(assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        SubElement(SubElement(decrypted_assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # No signature must be found
        self.assertIsNone(SAMLResponse(ElementTree(root)).response_signature)

    def test_response_signature_exists(self):
        # Base structure
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        encrypted_assertion = SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        decrypted_assertion = SubElement(encrypted_assertion, Q_NAMES['saml2:Assertion'])
        # Place a few signature elements as booby traps
        SubElement(assertion, Q_NAMES['ds:Signature'])
        SubElement(decrypted_assertion, Q_NAMES['ds:Signature'])
        SubElement(SubElement(assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        SubElement(SubElement(decrypted_assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # This one must be found
        signature = SubElement(root, Q_NAMES['ds:Signature'])
        self.assertIs(SAMLResponse(ElementTree(root)).response_signature, signature)

    def test_assertion_signature_not_exists(self):
        # Base structure
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        # Place a few signature elements as booby traps
        SubElement(root, Q_NAMES['ds:Signature'])
        SubElement(SubElement(assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        self.assertIsNone(SAMLResponse(ElementTree(root)).assertion_signature)

    def test_assertion_signature_exists(self):
        # Base structure
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        # Place a few signature elements as booby traps
        SubElement(root, Q_NAMES['ds:Signature'])
        SubElement(SubElement(assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # This one must be found
        signature = SubElement(assertion, Q_NAMES['ds:Signature'])
        self.assertIs(SAMLResponse(ElementTree(root)).assertion_signature, signature)

    def test_assertion_signature_exists_decrypted(self):
        # Base structure
        root = Element(Q_NAMES['saml2p:Response'])
        encrypted_assertion = SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        decrypted_assertion = SubElement(encrypted_assertion, Q_NAMES['saml2:Assertion'])
        # Place a few signature elements as booby traps
        SubElement(root, Q_NAMES['ds:Signature'])
        SubElement(SubElement(decrypted_assertion, Q_NAMES['saml2:Issuer']), Q_NAMES['ds:Signature'])
        # This one must be found
        signature = SubElement(decrypted_assertion, Q_NAMES['ds:Signature'])
        self.assertIs(SAMLResponse(ElementTree(root)).assertion_signature, signature)

    def test_sign_response(self):
        root = Element(Q_NAMES['saml2p:Response'])
        SubElement(root, Q_NAMES['saml2:Assertion'])
        response = SAMLResponse(ElementTree(root))
        response.sign_response(**SIGNATURE_OPTIONS)
        self.assertIsNotNone(response.response_signature)
        self.assertIsNone(response.assertion_signature)

    def test_sign_response_already_exists(self):
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        response_signature = SubElement(root, Q_NAMES['ds:Signature'])
        assertion_signature = SubElement(assertion, Q_NAMES['ds:Signature'])
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'The response signature is already present'):
            response.sign_response(**SIGNATURE_OPTIONS)
        self.assertIs(response.response_signature, response_signature)  # Preserved
        self.assertIs(response.assertion_signature, assertion_signature)  # Preserved

    def test_sign_assertion(self):
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        SubElement(assertion, Q_NAMES['saml2:Issuer'])
        response = SAMLResponse(ElementTree(root))
        self.assertTrue(response.sign_assertion(**SIGNATURE_OPTIONS))
        self.assertIsNone(response.response_signature)
        self.assertIsNotNone(response.assertion_signature)

    def test_sign_assertion_already_exists(self):
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(root, Q_NAMES['saml2:Assertion'])
        response_signature = SubElement(root, Q_NAMES['ds:Signature'])
        assertion_signature = SubElement(assertion, Q_NAMES['ds:Signature'])
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'The assertion signature is already present'):
            response.sign_assertion(**SIGNATURE_OPTIONS)
        self.assertIs(response.response_signature, response_signature)  # Preserved
        self.assertIs(response.assertion_signature, assertion_signature)  # Preserved

    def test_sign_assertion_response_signed(self):
        root = Element(Q_NAMES['saml2p:Response'])
        SubElement(root, Q_NAMES['saml2:Assertion'])
        response_signature = SubElement(root, Q_NAMES['ds:Signature'])
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'response signature is already present'):
            response.sign_assertion(**SIGNATURE_OPTIONS)
        self.assertIs(response.response_signature, response_signature)  # Preserved
        self.assertIsNone(response.assertion_signature)

    def test_sign_assertion_decrypted(self):
        root = Element(Q_NAMES['saml2p:Response'])
        assertion = SubElement(SubElement(root, Q_NAMES['saml2:EncryptedAssertion']), Q_NAMES['saml2:Assertion'])
        response_signature = SubElement(root, Q_NAMES['ds:Signature'])
        assertion_signature = SubElement(assertion, Q_NAMES['ds:Signature'])
        response = SAMLResponse(ElementTree(root))
        self.assertFalse(response.sign_assertion(**SIGNATURE_OPTIONS))
        self.assertIs(response.response_signature, response_signature)  # Preserved
        self.assertIs(response.assertion_signature, assertion_signature)  # Preserved

    def test_sign_assertion_no_assertion(self):
        root = Element(Q_NAMES['saml2p:Response'])
        response = SAMLResponse(ElementTree(root))
        self.assertFalse(response.sign_assertion(**SIGNATURE_OPTIONS))
        self.assertIsNone(response.response_signature)
        self.assertIsNone(response.assertion_signature)

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_and_remove_signature_none(self, signatures_mock):
        root = Element('root')
        signature = SubElement(root, 'signature')
        SubElement(root, 'child')
        signatures_mock.return_value = [SignatureInfo(signature, (root,))]
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'Signature does not exist'):
            response._verify_and_remove_signature(None, 'cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [])

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_and_remove_signature_not_found(self, signatures_mock):
        root = Element('root')
        signature = SubElement(root, 'signature')
        SubElement(root, 'child')
        signatures_mock.return_value = [SignatureInfo(signature, (root,))]
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'Signature not found'):
            response._verify_and_remove_signature(Element('signature2'), 'cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [call(root, 'cert.pem')])

    @patch('eidas_node.saml.verify_xml_signatures')
    def test_verify_and_remove_signature_bad_reference(self, signatures_mock):
        root = Element('root')
        signature = SubElement(root, 'signature')
        child = SubElement(root, 'child')
        signatures_mock.return_value = [SignatureInfo(signature, (child,))]
        response = SAMLResponse(ElementTree(root))
        with self.assertRaisesMessage(SecurityError, 'Signature does not reference parent element'):
            response._verify_and_remove_signature(signature, 'cert.pem')
        self.assertEqual(signatures_mock.mock_calls, [call(root, 'cert.pem')])

    def test_verify_assertion_without_assertion(self):
        with cast(TextIO, (DATA_DIR / 'signed_failed_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
            remove_extra_xml_whitespace(tree)

        response = SAMLResponse(tree)
        self.assertFalse(response.verify_assertion(CERT_FILE))

    def test_verify_response_without_assertion(self):
        with cast(TextIO, (DATA_DIR / 'signed_failed_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
            remove_extra_xml_whitespace(tree)

        response = SAMLResponse(tree)
        response.verify_response(CERT_FILE)

    def test_verify_response_nia(self):
        with cast(TextIO, (DATA_DIR / 'nia_test_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
            remove_extra_xml_whitespace(tree)

        response = SAMLResponse(tree)
        response.verify_response(NIA_CERT_FILE)

    def test_verify_assertion_nia_not_decrypted(self):
        with cast(TextIO, (DATA_DIR / 'nia_test_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
            remove_extra_xml_whitespace(tree)

        response = SAMLResponse(tree)
        self.assertFalse(response.verify_assertion(NIA_CERT_FILE))

    def test_verify_response_and_assertion_nia(self):
        with cast(TextIO, (DATA_DIR / 'nia_test_response.xml').open('r')) as f:
            tree = parse_xml(f.read())
            remove_extra_xml_whitespace(tree)

        response = SAMLResponse(tree)
        response.verify_response(NIA_CERT_FILE)
        response.decrypt(KEY_FILE)
        self.assertTrue(response.verify_assertion(NIA_CERT_FILE))


class TestCreateAttributeElmAttributes(SimpleTestCase):
    def test_create_attribute_elm_attributes_known_attribute(self):
        name = 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'
        self.assertEqual(create_attribute_elm_attributes(name, None), {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
            'FriendlyName': 'FamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        })

    def test_create_attribute_elm_attributes_unknown_attribute(self):
        name = 'http://eidas.europa.eu/attributes/naturalperson/ConcurrentFamilyName'
        self.assertEqual(create_attribute_elm_attributes(name, None), {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/ConcurrentFamilyName',
            'FriendlyName': 'ConcurrentFamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        })

    def test_create_attribute_elm_attributes_required(self):
        name = 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'
        self.assertEqual(create_attribute_elm_attributes(name, True), {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
            'FriendlyName': 'FamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'isRequired': 'true',
        })

    def test_create_attribute_elm_attributes_optional(self):
        name = 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'
        self.assertEqual(create_attribute_elm_attributes(name, False), {
            'Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
            'FriendlyName': 'FamilyName',
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'isRequired': 'false',
        })
