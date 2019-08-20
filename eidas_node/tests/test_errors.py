from django.test import SimpleTestCase

from eidas_node.errors import ValidationError


class TestValidationError(SimpleTestCase):
    ERRORS = {'name': 'Invalid name.'}

    def test_errors_attribute(self):
        self.assertIs(ValidationError(self.ERRORS).errors, self.ERRORS)

    def test_repr(self):
        self.assertEquals(repr(ValidationError(self.ERRORS)), "ValidationError({'name': 'Invalid name.'})")

    def test_str(self):
        self.assertEquals(str(ValidationError(self.ERRORS)), "Validation failed: {'name': 'Invalid name.'}")
