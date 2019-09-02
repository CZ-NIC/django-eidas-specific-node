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
