"""Models of eidas_node."""
import hashlib
import hmac
from base64 import b64decode, b64encode
from datetime import datetime

from eidas_node.errors import ParseError, SecurityError, ValidationError

from .datamodels import DataModel
from .utils import create_eidas_timestamp, parse_eidas_timestamp


class LightToken(DataModel):
    """
    eIDAS-Node Light Token.

    See eIDAS-Node National IdP and SP Integration Guide version 2.3: 4.4.1. Implementing the LightToken.
    """

    FIELDS = ['id', 'issuer', 'created']
    id = None  # type: str
    """A unique identifier to reference the real data object (LightRequest/LightResponse)."""
    issuer = None  # type: str
    """A simple text string that helps identify (debug) which component is sending the redirect."""
    created = None  # type: datetime
    """A timestamp showing when the LightToken was created."""

    def validate(self) -> None:
        """Validate this data model."""
        self.validate_fields(str, 'id', 'issuer', required=True)
        self.validate_fields(datetime, 'created', required=True)
        for field in 'id', 'issuer':
            if '|' in getattr(self, field):
                raise ValidationError({field: 'Character "|" not allowed.'})

    def digest(self, hash_algorithm: str, secret: str) -> bytes:
        """
        Calculate the digest of the token.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Digest as raw bytes (not base64 encoded).
        :raise ValidationError: If token data are invalid.
        """
        self.validate()
        data = '|'.join((self.id, self.issuer, create_eidas_timestamp(self.created), secret))
        algorithm = hashlib.new(hash_algorithm)
        algorithm.update(data.encode('utf-8'))
        return algorithm.digest()

    def encode(self, hash_algorithm: str, secret: str) -> bytes:
        """
        Encode token for transmission.

        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :return: Base64 encoded token as bytes.
        :raise ValidationError: If token data are invalid.
        """
        digest = b64encode(self.digest(hash_algorithm, secret)).decode('ascii')
        data = '|'.join((self.issuer, self.id, create_eidas_timestamp(self.created), digest))
        return b64encode(data.encode('utf-8'))

    @classmethod
    def decode(cls, encoded_token: bytes, hash_algorithm: str, secret: str, max_size: int = 1024) -> 'LightToken':
        """
        Decode encoded token and check the validity and digest.

        :param encoded_token:  Base64 encoded token.
        :param hash_algorithm: One of hashlib hash algorithms.
        :param secret: The secret shared between the communicating parties.
        :param max_size: The maximal size of the encoded token.
        :return: Decoded and validated token.
        :raise ParseError: If the token is malformed and cannot be decoded.
        :raise ValidationError: If the token can be decoded but model validation fails.
        :raise SecurityError: If the token digest is invalid.
        """
        if max_size and len(encoded_token) > max_size:
            raise ParseError('Maximal token size exceeded.')
        data = b64decode(encoded_token, validate=True).decode('utf-8')
        try:
            issuer, token_id, timestamp, digest_base64 = data.split('|')
        except ValueError as e:
            raise ParseError('Token has wrong number of parts: {}.'.format(e.args[0]))

        token = LightToken(issuer=issuer, id=token_id, created=parse_eidas_timestamp(timestamp))
        token.validate()

        provided_digest = b64decode(digest_base64.encode('ascii'))
        valid_digest = token.digest(hash_algorithm, secret)
        if not hmac.compare_digest(valid_digest, provided_digest):
            raise SecurityError('Light token has invalid digest.')
        return token
