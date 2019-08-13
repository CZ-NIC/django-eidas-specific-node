from django.test import SimpleTestCase

from eidas_node.errors import ParseError, SecurityError, ValidationError


class TestValidationError(SimpleTestCase):
    ERRORS = {'name': 'Invalid name.'}

    def test_errors_attribute(self):
        self.assertIs(ValidationError(self.ERRORS).errors, self.ERRORS)

    def test_repr(self):
        self.assertEqual(repr(ValidationError(self.ERRORS)), "ValidationError({'name': 'Invalid name.'})")

    def test_str(self):
        self.assertEqual(str(ValidationError(self.ERRORS)), "Validation failed: {'name': 'Invalid name.'}")


class TestParseError(SimpleTestCase):
    ERROR = 'Parsing failed.'

    def test_error_attribute(self):
        self.assertIs(ParseError(self.ERROR).error, self.ERROR)

    def test_repr(self):
        self.assertEqual(repr(ParseError(self.ERROR)), "ParseError('Parsing failed.')")

    def test_str(self):
        self.assertEqual(str(ParseError(self.ERROR)), 'Parsing failed.')


class TestSecurityError(SimpleTestCase):
    ERROR = 'Signature does not match.'

    def test_error_attribute(self):
        self.assertIs(SecurityError(self.ERROR).error, self.ERROR)

    def test_repr(self):
        self.assertEqual(repr(SecurityError(self.ERROR)), "SecurityError('Signature does not match.')")

    def test_str(self):
        self.assertEqual(str(SecurityError(self.ERROR)), 'Signature does not match.')
