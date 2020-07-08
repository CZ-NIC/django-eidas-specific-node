"""Storage for Light Requests and Responses."""

from eidas_node.storage.base import AuxiliaryStorage, LightStorage
from eidas_node.storage.utils import get_auxiliary_storage

__all__ = ['AuxiliaryStorage', 'LightStorage', 'get_auxiliary_storage']
