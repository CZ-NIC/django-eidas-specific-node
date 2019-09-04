"""Various utility functions."""
import re
from datetime import datetime
from importlib import import_module
from io import BytesIO
from typing import Any, BinaryIO, List, Union
from uuid import uuid4

from lxml import etree

VALID_XML_ID_RE = re.compile('^[_a-zA-Z][-._a-zA-Z0-9]*$')


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


def parse_xml(xml: Union[str, bytes, BinaryIO]) -> etree.ElementTree:
    """Parse a XML document."""
    if isinstance(xml, str):
        xml = xml.encode('utf-8')
    if isinstance(xml, bytes):
        xml = BytesIO(xml)
    return etree.parse(xml)


def dump_xml(xml: etree.ElementTree, pretty_print: bool = True, encoding: str = 'utf-8',
             xml_declaration: bool = True, standalone: bool = True) -> bytes:
    """Export an element tree as a XML document."""
    return etree.tostring(xml, pretty_print=pretty_print, encoding=encoding,
                          xml_declaration=xml_declaration, standalone=standalone)


def get_element_path(elm: etree.Element) -> str:
    """Create an element path from the root element."""
    path = []  # type: List[str]
    while elm is not None:
        q_name = etree.QName(elm.tag)
        tag = q_name.localname
        for key, namespace in elm.nsmap.items():
            if key and namespace == q_name.namespace:
                tag = '{}:{}'.format(key, q_name.localname)
                break

        path.append('<{}>'.format(tag))
        elm = elm.getparent()
    path.reverse()
    return ''.join(path)


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


def is_xml_id_valid(xml_id: str) -> bool:
    """Check whether the provided id is a valid XML id."""
    return VALID_XML_ID_RE.match(xml_id) is not None


def create_xml_uuid(prefix: str = '_') -> str:
    """
    Create a UUID which is also a valid XML id.

    :param prefix: UUID prefix. It must start with a letter or underscore.
    :return: A prefixed UUID.
    """
    if not is_xml_id_valid(prefix):
        raise ValueError('Invalid prefix: {!r}'.format(prefix))
    return prefix + str(uuid4())
