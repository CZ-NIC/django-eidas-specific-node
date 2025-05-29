"""Storage utility functions."""

from typing import Any, Dict

from eidas_node.storage.base import AuxiliaryStorage
from eidas_node.utils import import_from_module


def get_auxiliary_storage(backend: str, options: Dict[str, Any]) -> AuxiliaryStorage:
    """
    Create an auxiliary storage instance.

    :param backend: A fully qualified name of the backend class.
    :param options: The options to pass to the backend.
    :return: An auxiliary storage instance.
    """
    return import_from_module(backend)(**options)
