from base64 import b64decode
from datetime import datetime
from typing import Any, Dict, cast
from unittest import mock

from django.test import SimpleTestCase

from eidas_node.errors import ParseError, SecurityError, ValidationError
from eidas_node.models import LightToken


class ValidationMixin:
    # Model to validate
    MODEL = None  # type: type
    # Example of valid data
    VALID_DATA = None  # type: Dict[str, Any]
    # Invalid data for basic type checks. Extra checks must have own test method.
    INVALID_DATA = None  # type: Dict[str, Any]

    def test_valid(self):
        self.MODEL(**self.VALID_DATA).validate()

    def test_required(self):
        t = cast(SimpleTestCase, self)
        for name in self.VALID_DATA:
            with t.subTest(name=name):
                data = self.VALID_DATA.copy()
                del data[name]
                t.assertRaises(ValidationError, self.MODEL(**data).validate)

    def test_invalid(self):
        t = cast(SimpleTestCase, self)
        for name in self.INVALID_DATA:
            with t.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] = self.INVALID_DATA[name]
                t.assertRaises(ValidationError, self.MODEL(**data).validate)


class TestLightToken(ValidationMixin, SimpleTestCase):
    MODEL = LightToken
    VALID_DATA = {
        'id': '852a64c0-8ac1-445f-b0e1-992ada493033',
        'issuer': 'specificCommunicationDefinitionConnectorRequest',
        'created': datetime(2017, 12, 11, 14, 12, 5, 148000),
    }
    INVALID_DATA = {
        'id': 123,
        'issuer': b'specificCommunicationDefinitionConnectorRequest',
        'created': '2017-12-11 14:12:05 148',
    }
    SECRET = 'mySecretConnectorRequest'
    ENCODED_TOKEN = (b'c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0'
                     b'0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk'
                     b'lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWUU9')

    def get_token(self, **kwargs) -> LightToken:
        data = self.VALID_DATA.copy()
        data.update(**kwargs)
        return LightToken(**data)

    def test_pipe_character_not_allowed(self):
        for name in 'id', 'issuer':
            with self.subTest(name=name):
                data = self.VALID_DATA.copy()
                data[name] += '|pipe'
                self.assertRaises(ValidationError, self.MODEL(**data).validate)

    def test_digest(self):
        token = self.get_token()
        digest = token.digest('sha256', self.SECRET)
        expected_digest = b64decode(b'7M8p+uP8CKXuMi2IqSda1tg452WlRvcOSwu0dcisSYE=')
        self.assertEqual(expected_digest, digest)

    def test_encode(self):
        token = self.get_token()
        self.assertEqual(token.encode('sha256', self.SECRET), self.ENCODED_TOKEN)

    def test_decode_ok(self):
        self.assertEqual(LightToken.decode(self.ENCODED_TOKEN, 'sha256', self.SECRET), self.get_token())

    def test_decode_validation_error(self):
        with mock.patch.object(LightToken, 'validate'):
            encoded = self.get_token(issuer='').encode('sha256', self.SECRET)

        with self.assertRaisesMessage(ValidationError, 'Must be str, not NoneType'):
            LightToken.decode(encoded, 'sha256', self.SECRET)

    def test_decode_max_size_exceeded(self):
        with self.assertRaisesMessage(ParseError, 'Maximal token size exceeded.'):
            LightToken.decode(self.ENCODED_TOKEN * 100, 'sha256', self.SECRET)

    def test_decode_wrong_number_of_parts(self):
        token = self.get_token(issuer='specificCommunicationDefinitionConnectorRequest|extra')
        with mock.patch.object(LightToken, 'validate'):
            encoded = token.encode('sha256', self.SECRET)

        with self.assertRaisesMessage(ParseError, 'wrong number of parts'):
            LightToken.decode(encoded, 'sha256', self.SECRET)

    def test_decode_wrong_secret(self):
        with self.assertRaisesMessage(SecurityError, 'invalid digest'):
            LightToken.decode(self.ENCODED_TOKEN, 'sha256', 'Dycky Most!')

    def test_decode_wrong_digest(self):
        encoded = (b'c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlcXVlc3R8ODUyYTY0YzAtOGFjMS0'
                   b'0NDVmLWIwZTEtOTkyYWRhNDkzMDMzfDIwMTctMTItMTEgMTQ6MTI6MDUgMTQ4fDdNOHArdVA4Q0tYdU1pMk'
                   b'lxU2RhMXRnNDUyV2xSdmNPU3d1MGRjaXNTWWs9')
        with self.assertRaisesMessage(SecurityError, 'invalid digest'):
            LightToken.decode(encoded, 'sha256', self.SECRET)
