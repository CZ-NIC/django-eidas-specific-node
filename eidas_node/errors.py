"""Errors of eidas_node."""
from typing import Dict


class EidasNodeError(Exception):
    """Base error of eidas_node package."""


class ValidationError(EidasNodeError):
    """
    Error for validation failures.

    :param errors: A dictionary of field names (keys) and error messages (values).
    """

    def __init__(self, errors: Dict[str, str]):
        self.errors = errors

    def __str__(self) -> str:
        return 'Validation failed: {!r}'.format(self.errors)

    def __repr__(self) -> str:
        return '{}({!r})'.format(self.__class__.__name__, self.errors)


class ParseError(EidasNodeError):
    """
    Error for parsing and decoding failures.

    :param error: An error message.
    """

    def __init__(self, error: str):
        self.error = error

    def __str__(self) -> str:
        return self.error

    def __repr__(self) -> str:
        return '{}({!r})'.format(self.__class__.__name__, self.error)


class SecurityError(EidasNodeError):
    """
    Error for signature and encryption failures.

    :param error: An error message.
    """

    def __init__(self, error: str):
        self.error = error

    def __str__(self) -> str:
        return self.error

    def __repr__(self) -> str:
        return '{}({!r})'.format(self.__class__.__name__, self.error)
