"""Abstract Storage for Light Requests and Responses."""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from eidas_node.models import LightRequest, LightResponse

LOGGER = logging.getLogger('eidas_node.storage')


class LightStorage(ABC):
    """
    Storage for Light Requests and Responses.

    There is no guarantee of thread safety of the implementations,
    so a storage instance should not be shared among individual requests.
    """

    @abstractmethod
    def pop_light_request(self, uid: str) -> Optional[LightRequest]:
        """Look up a LightRequest by a unique id and then remove it."""

    @abstractmethod
    def pop_light_response(self, uid: str) -> Optional[LightResponse]:
        """Look up a LightResponse by a unique id and then remove it."""

    @abstractmethod
    def put_light_request(self, uid: str, request: LightRequest) -> None:
        """Store a LightRequest under a unique id."""

    @abstractmethod
    def put_light_response(self, uid: str, response: LightResponse) -> None:
        """Store a LightRequest under a unique id."""


class AuxiliaryStorage(ABC):
    """
    Storage for auxiliary data.

    There is no guarantee of thread safety of the implementations,
    so a storage instance should not be shared among individual requests.
    """

    @abstractmethod
    def pop(self, uid: str) -> Optional[Dict[str, Any]]:
        """Look up data by a unique id and then remove it."""

    @abstractmethod
    def put(self, uid: str, data: Dict[str, Any]) -> None:
        """Store data under a unique id."""
