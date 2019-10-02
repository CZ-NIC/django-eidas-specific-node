"""Various utility functions."""
import sys
from datetime import datetime
from importlib import import_module
from threading import Lock
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


class WrappedSeries:
    """Thread-safe series of integers wrapped at a maximal value."""

    def __init__(self, start: int = 1, wrap: int = sys.maxsize):
        self._start = start
        self._next = start
        self._wrap = wrap
        self._lock = Lock()

    def next(self) -> int:
        """
        Get the next number from the series.

        This method is thread-safe.
        """
        with self._lock:
            value = self._next
            self._next = self._start if value == self._wrap else value + 1
        return value
