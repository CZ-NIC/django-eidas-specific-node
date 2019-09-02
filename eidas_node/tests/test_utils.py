from datetime import datetime
from io import BytesIO

from django.test import SimpleTestCase
from lxml.etree import Element, SubElement

from eidas_node.saml import NAMESPACES, Q_NAMES
from eidas_node.utils import (create_eidas_timestamp, datetime_iso_format_milliseconds, get_element_path,
                              import_from_module, parse_eidas_timestamp, parse_xml)


class TestTimestampUtils(SimpleTestCase):
    TIMESTAMP = '2017-12-11 14:12:05 148'
    DATETIME = datetime(2017, 12, 11, 14, 12, 5, 148000)

    def test_parse_eidas_timestamp(self):
        self.assertEqual(parse_eidas_timestamp(self.TIMESTAMP), self.DATETIME)
        self.assertRaises(ValueError, parse_eidas_timestamp, self.TIMESTAMP + '000')

    def test_create_eidas_timestamp(self):
        self.assertEqual(create_eidas_timestamp(self.DATETIME), self.TIMESTAMP)
        self.assertEqual(create_eidas_timestamp(self.DATETIME.replace(microsecond=148765)), self.TIMESTAMP)

    def test_datetime_iso_format_milliseconds(self):
        self.assertEqual(datetime_iso_format_milliseconds(datetime(2017, 12, 11, 14, 12, 5, 148666)),
                         '2017-12-11T14:12:05.148')
        self.assertEqual(datetime_iso_format_milliseconds(datetime(2017, 12, 11, 14, 12, 5, 148000)),
                         '2017-12-11T14:12:05.148')
        self.assertEqual(datetime_iso_format_milliseconds(datetime(2017, 12, 11, 14, 12, 5, 0)),
                         '2017-12-11T14:12:05.000')
        self.assertEqual(datetime_iso_format_milliseconds(datetime(2017, 12, 11, 14, 12, 0, 0)),
                         '2017-12-11T14:12:00.000')


class TestXML(SimpleTestCase):
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


class TestImport(SimpleTestCase):
    def test_import_from_module(self):
        result = import_from_module('http.server.HTTPServer')
        from http.server import HTTPServer
        self.assertIs(result, HTTPServer)

    def test_import_from_module_invalid_name(self):
        with self.assertRaisesMessage(ValueError, "Invalid fully qualified name: 'OnlyClassName'."):
            import_from_module('OnlyClassName')

    def test_import_from_module_member_not_found(self):
        with self.assertRaisesMessage(ImportError, 'ThisClassDoesNotExist not found in http.server.'):
            import_from_module('http.server.ThisClassDoesNotExist')
