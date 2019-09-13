"""XML utility functions."""
import re
from io import BytesIO
from typing import BinaryIO, List, Union
from uuid import uuid4

import xmlsec
from lxml import etree
from lxml.etree import ElementTree

VALID_XML_ID_RE = re.compile('^[_a-zA-Z][-._a-zA-Z0-9]*$')
XML_ENC_NAMESPACE = 'http://www.w3.org/2001/04/xmlenc#'


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


def decrypt_xml(tree: ElementTree, key_file: str) -> None:
    """
    Decrypt a XML document.

    :param tree: The XML document to decrypt.
    :param key_file: A path to an encryption key file.
    """
    encrypted_elements = tree.findall(".//{%s}EncryptedData" % XML_ENC_NAMESPACE)
    if encrypted_elements:
        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(key_file, xmlsec.constants.KeyDataFormatPem))
        enc_ctx = xmlsec.EncryptionContext(manager)
        for elm in encrypted_elements:
            enc_ctx.decrypt(elm)

        # Fix pretty printing
        for elm in tree.iter():
            if elm.tail is not None and elm.tail.isspace():
                elm.tail = None
            if elm.text is not None and elm.text.isspace():
                elm.text = None
