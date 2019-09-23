"""Various utility functions."""
from datetime import datetime
from importlib import import_module
from typing import Any


def parse_eidas_timestamp(timestamp: str) -> datetime:
    """Parse a date & time string in eIDAS format."""
    return datetime.strptime(timestamp + '000', '%Y-%m-%d %H:%M:%S %f')


def create_eidas_timestamp(timestamp: datetime) -> str:
    """Create a date & time string in eIDAS format."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S %f")[:-3]


def datetime_iso_format_milliseconds(timestamp: datetime) -> str:
    """Return a string representing the date and time in ISO 8601 format trimmed to milliseconds."""
    # TODO: Python 3.6: datetime.isoformat(timespec='milliseconds')
    return timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]


def import_from_module(name: str) -> Any:
    """
    Import a module member specified by a fully qualified name.

    :param name: A fully qualified name (`package.module.ClassName`).
    :return: The requested module member.
    :raise ImportError: If the requested member cannot be imported.
    :raise ValueError: If the `name` is not a fully qualified name.
    """
    try:
        module_name, class_name = name.rsplit('.', 1)
    except ValueError:
        raise ValueError('Invalid fully qualified name: {!r}.'.format(name)) from None

    module = import_module(module_name)
    try:
        return getattr(module, class_name)
    except AttributeError:
        raise ImportError('{} not found in {}.'.format(class_name, module_name)) from None
