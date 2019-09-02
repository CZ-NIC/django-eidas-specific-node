from datetime import datetime
from io import BytesIO

from django.test import SimpleTestCase
from lxml.etree import Element, SubElement

from eidas_node.utils import create_eidas_timestamp, get_element_path, parse_eidas_timestamp, parse_xml


class TestEidasTimestamp(SimpleTestCase):
    TIMESTAMP = '2017-12-11 14:12:05 148'
    DATETIME = datetime(2017, 12, 11, 14, 12, 5, 148000)

    def test_parse_eidas_timestamp(self):
        self.assertEqual(parse_eidas_timestamp(self.TIMESTAMP), self.DATETIME)
        self.assertRaises(ValueError, parse_eidas_timestamp, self.TIMESTAMP + '000')

    def test_create_eidas_timestamp(self):
        self.assertEqual(create_eidas_timestamp(self.DATETIME), self.TIMESTAMP)
        self.assertEqual(create_eidas_timestamp(self.DATETIME.replace(microsecond=148765)), self.TIMESTAMP)


class TestXML(SimpleTestCase):
    def test_parse_xml_data_types(self):
        binary = b'<lightRequest></lightRequest>'
        parse_xml(binary)
        parse_xml(binary.decode('ascii'))
        parse_xml(BytesIO(binary))

    def test_get_element_path(self):
        root = Element('root')
        grandchild = SubElement(SubElement(root, 'child'), 'grandchild')
        self.assertEqual(get_element_path(root), '<root>')
        self.assertEqual(get_element_path(grandchild), '<root><child><grandchild>')
