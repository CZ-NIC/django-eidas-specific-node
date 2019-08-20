"""Various utility functions."""
from datetime import datetime
from io import BytesIO
from typing import BinaryIO, List, Union

from lxml import etree


def parse_eidas_timestamp(timestamp: str) -> datetime:
    """Parse a date & time string in eIDAS format."""
    return datetime.strptime(timestamp + '000', '%Y-%m-%d %H:%M:%S %f')


def create_eidas_timestamp(timestamp: datetime) -> str:
    """Create a date & time string in eIDAS format."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S %f")[:-3]


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
        path.append('<{}>'.format(elm.tag))
        elm = elm.getparent()
    path.reverse()
    return ''.join(path)
