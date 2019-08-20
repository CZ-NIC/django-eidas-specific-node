"""
Lightweight data models.

The declaration of a data model is as simple as:

.. code:: python

    class User(DataModel):
        FIELDS = ['name', 'age']
        name = None  # type: str
        age = None  # type: int

        def validate(self) -> None:
            ...
"""
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Dict, Iterator, List, Tuple, Type

from eidas_node.errors import ValidationError


class DataModel(ABC):
    """
    A simple model holding data fields.

    :param data: Initial data for model fields.
    :raise TypeError: On unexpected keyword argument or if a value for a field without a default value is not provided.
    """

    FIELDS = None  # type: List[str]
    """Names of data fields."""

    def __init__(self, **data: Any) -> None:
        if self.FIELDS is None:
            raise TypeError('DataModel subclasses must define FIELDS class attribute.')
        fields = set(self.FIELDS)
        for name, value in data.items():
            try:
                fields.remove(name)
            except KeyError:
                raise TypeError('{}.__init__() got an unexpected keyword argument {!r}'
                                .format(self.__class__.__name__, name))
            else:
                setattr(self, name, value)
        for name in fields:
            if not hasattr(self, name):
                raise TypeError('{}.__init__(): a missing keyword argument {!r} for a field without default value'
                                .format(self.__class__.__name__, name))

    def get_data_as_tuple(self) -> Tuple[Any, ...]:
        """Return the values of fields in the declared order."""
        return tuple(value.get_data_as_tuple() if isinstance(value, DataModel) else value for value in self)

    def get_data_as_dict(self) -> Dict[str, Any]:
        """Return the names and values of fields in the declared order."""
        result = OrderedDict()  # type: Dict[str, Any]
        for name in self.FIELDS:
            value = getattr(self, name)
            result[name] = value.get_data_as_dict() if isinstance(value, DataModel) else value
        return result

    @abstractmethod
    def validate(self) -> None:
        """Validate this data model."""

    def validate_fields(self, required_type: Type, *fields: str, required: bool = True) -> None:
        """
        Validate fields.

        :param required_type: The required type of the field.
        :param fields: The fields to validate.
        :param required: Whether the field is required or can be None.
        :raise ValidationError: when validation fails.
        """
        for name in fields:
            value = getattr(self, name)
            if isinstance(value, str) and not value:
                value = None  # Treat empty strings as None
            if not isinstance(value, required_type):
                if required:
                    raise ValidationError(
                        {name: 'Must be {}, not {}.'.format(required_type.__name__, type(value).__name__)})
                if value is not None:
                    raise ValidationError(
                        {name: 'Must be {} or None, not {}.'.format(required_type.__name__, type(value).__name__)})

    def __iter__(self) -> Iterator[Any]:
        """Iterate over values of all fields."""
        return (getattr(self, name) for name in self.FIELDS)

    def __repr__(self) -> str:
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join('{}={!r}'.format(key, getattr(self, key)) for key in self.FIELDS)
        )

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DataModel):
            return NotImplemented
        return type(self) is type(other) and self.get_data_as_tuple() == other.get_data_as_tuple()
