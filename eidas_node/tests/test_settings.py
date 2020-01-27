from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from eidas_node.constants import XmlBlockCipher
from eidas_node.settings import EnumSetting


class TestEnumSetting(SimpleTestCase):
    def test_transform_valid(self):
        setting = EnumSetting(XmlBlockCipher)
        self.assertIs(setting.transform('AES128_GCM'), XmlBlockCipher.AES128_GCM)

    def test_transform_invalid(self):
        setting = EnumSetting(XmlBlockCipher)
        self.assertRaises(KeyError, setting.transform, None)
        self.assertRaises(KeyError, setting.transform, 1)
        self.assertRaises(KeyError, setting.transform, 'plaintext')

    def test_validate_valid(self):
        setting = EnumSetting(XmlBlockCipher)
        setting.validate('AES128_GCM')

    def test_validate_invalid(self):
        setting = EnumSetting(XmlBlockCipher)
        self.assertRaises(ValidationError, setting.validate, None)
        self.assertRaises(ValidationError, setting.validate, 1)
        self.assertRaises(ValidationError, setting.validate, 'plaintext')
