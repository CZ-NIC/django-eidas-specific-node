from datetime import datetime

from django.test import SimpleTestCase

from eidas_node.utils import create_eidas_timestamp, parse_eidas_timestamp


class TestEidasTimestamp(SimpleTestCase):
    TIMESTAMP = '2017-12-11 14:12:05 148'
    DATETIME = datetime(2017, 12, 11, 14, 12, 5, 148000)

    def test_parse_eidas_timestamp(self):
        self.assertEqual(parse_eidas_timestamp(self.TIMESTAMP), self.DATETIME)
        self.assertRaises(ValueError, parse_eidas_timestamp, self.TIMESTAMP + '000')

    def test_create_eidas_timestamp(self):
        self.assertEqual(create_eidas_timestamp(self.DATETIME), self.TIMESTAMP)
        self.assertEqual(create_eidas_timestamp(self.DATETIME.replace(microsecond=148765)), self.TIMESTAMP)
