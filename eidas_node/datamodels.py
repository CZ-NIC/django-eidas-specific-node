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
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
from enum import Enum
from typing import Any, Dict, Iterator, List, Tuple, Type, TypeVar, Union

from lxml.etree import Element, ElementTree, SubElement, QName

from eidas_node.errors import ValidationError
from eidas_node.xml import get_element_path


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


T = TypeVar('T', bound='XMLDataModel')


class XMLDataModel(DataModel, ABC):
    """Data model with XML serialization and deserialization."""

    ROOT_ELEMENT = None  # type: str
    """The name of the root element."""

    ROOT_NS = None  # type: str
    """Namespace of the root element."""

    def export_xml(self) -> Element:
        """
        Export LightRequest as a XML document.

        :return: A XML document.
        :raise ValidationError: If the model validation fails.
        """
        self.validate()
        if not self.ROOT_ELEMENT:
            raise TypeError('XMLDataModel subclasses must define ROOT_ELEMENT class attribute.')
        root_nsmap = {} if not self.ROOT_NS else {None: self.ROOT_NS}
        root = Element(self.ROOT_ELEMENT, nsmap=root_nsmap)
        self.serialize_fields(root)
        return root

    def serialize_fields(self, parent_element: Element) -> None:
        """Serialize model fields."""
        for field_name in self.FIELDS:
            value = getattr(self, field_name)
            tag = convert_field_name_to_tag_name(field_name)
            serialize_func = getattr(self, 'serialize_' + field_name, None)
            if serialize_func:
                serialize_func(parent_element, tag, value)
            elif value is not None:
                if isinstance(value, XMLDataModel):
                    value.serialize_fields(SubElement(parent_element, tag))
                else:
                    if isinstance(value, Enum):
                        value = value.value
                    elif isinstance(value, bool):
                        value = str(value).lower()
                    else:
                        value = str(value)
                    SubElement(parent_element, tag).text = value

    @classmethod
    def load_xml(cls: Type[T], root: Union[Element, ElementTree]) -> T:
        """
        Load Light Request from a XML document.

        :param root: The XML document to load.
        :raise ValidationError: If the XML document does not have a valid schema.
        :raise TypeError: If ROOT_ELEMENT class attribute is not defined.
        """
        if not cls.ROOT_ELEMENT:
            raise TypeError('XMLDataModel subclasses must define ROOT_ELEMENT class attribute.')

        if hasattr(root, 'getroot'):
            root = root.getroot()

        if QName(root.tag).localname != cls.ROOT_ELEMENT:
            raise ValidationError({get_element_path(root): 'Invalid root element {!r}.'.format(root.tag)})

        model = cls()
        for elm in root:
            field_name = convert_tag_name_to_field_name(elm.tag)
            if field_name not in cls.FIELDS:
                raise ValidationError({get_element_path(elm): 'Unknown element {!r}.'.format(elm.tag)})

            deserialize_func = getattr(model, 'deserialize_' + field_name, None)
            setattr(model, field_name, deserialize_func(elm) if deserialize_func else elm.text)
        return model


def convert_tag_name_to_field_name(tag_name: str) -> str:
    """
    Convert a XML tag name to a field name.

    :param tag_name: A tag name ('nameIdFormat').
    :return: A field name ('name_id_format').
    """
    return re.sub('([A-Z]+)', r'_\1', QName(tag_name).localname).lower()


def convert_field_name_to_tag_name(field_name: str) -> str:
    """
    Convert a field name to a XML tag name.

    :param field_name: A field name ('name_id_format').
    :return: A XML tag name ('nameIdFormat').
    """
    tag_name = field_name.title().replace('_', '')
    return tag_name[0].lower() + tag_name[1:]
