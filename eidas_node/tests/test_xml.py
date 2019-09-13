from io import BytesIO
from typing import BinaryIO, cast
from unittest.mock import Mock, patch

import xmlsec
from django.test import SimpleTestCase
from lxml.etree import Element, SubElement

from eidas_node.saml import NAMESPACES, Q_NAMES
from eidas_node.tests.test_saml import DATA_DIR
from eidas_node.xml import create_xml_uuid, decrypt_xml, dump_xml, get_element_path, is_xml_id_valid, parse_xml


class TestGetElementPath(SimpleTestCase):
    def test_parse_xml_data_types(self):
        binary = b'<lightRequest></lightRequest>'
        parse_xml(binary)
        parse_xml(binary.decode('ascii'))
        parse_xml(BytesIO(binary))

    def test_get_element_path_without_namespaces(self):
        root = Element('root')
        grandchild = SubElement(SubElement(root, 'child'), 'grandchild')
        self.assertEqual(get_element_path(root), '<root>')
        self.assertEqual(get_element_path(grandchild), '<root><child><grandchild>')

    def test_get_element_path_with_namespaces(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        leaf = SubElement(root, Q_NAMES['saml2:EncryptedAssertion'])
        self.assertEqual(get_element_path(root), '<saml2p:Response>')
        self.assertEqual(get_element_path(leaf), '<saml2p:Response><saml2:EncryptedAssertion>')

    def test_get_element_path_mixed(self):
        root = Element(Q_NAMES['saml2p:Response'], nsmap=NAMESPACES)
        leaf = SubElement(SubElement(root, Q_NAMES['saml2:EncryptedAssertion']), 'wrong')
        self.assertEqual(get_element_path(root), '<saml2p:Response>')
        self.assertEqual(get_element_path(leaf), '<saml2p:Response><saml2:EncryptedAssertion><wrong>')


class TestValidXMLID(SimpleTestCase):
    def test_is_xml_id_valid_success(self):
        for value in 'aA5', 'a.5', 'a-5', '_5':
            self.assertTrue(is_xml_id_valid(value))

    def test_is_xml_id_valid_failure(self):
        for value in '0a', '.a', '-a', '#a', 'a#', 'a:a':
            self.assertFalse(is_xml_id_valid(value))

    @patch('eidas_node.xml.uuid4', return_value='0uuid4')
    def test_create_xml_uuid_default_prefix(self, _uuid_mock: Mock):
        self.assertEqual(create_xml_uuid(), '_0uuid4')

    @patch('eidas_node.xml.uuid4', return_value='0uuid4')
    def test_create_xml_uuid_valid_prefix(self, _uuid_mock: Mock):
        self.assertEqual(create_xml_uuid('T'), 'T0uuid4')

    @patch('eidas_node.xml.uuid4', return_value='0uuid4')
    def test_create_xml_uuid_invalid_prefix(self, _uuid_mock: Mock):
        for prefix in '', '-', '#':
            self.assertRaisesMessage(ValueError, 'Invalid prefix', create_xml_uuid, prefix)


class TestDecryptXML(SimpleTestCase):
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
