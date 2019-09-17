"""XML utility functions."""
import re
from io import BytesIO
from typing import BinaryIO, List, Union
from uuid import uuid4

import xmlsec
from lxml import etree
from lxml.etree import Element, ElementTree

VALID_XML_ID_RE = re.compile('^[_a-zA-Z][-._a-zA-Z0-9]*$')
XML_ENC_NAMESPACE = 'http://www.w3.org/2001/04/xmlenc#'
XML_SIG_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
XML_ATTRIBUTE_ID = 'ID'


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

        remove_extra_xml_whitespace(tree.getroot())


def remove_extra_xml_whitespace(node: Element) -> None:
    """Remove insignificant XML whitespace."""
    for elm in node.iter():
        if not elm.tail or elm.tail.isspace():
            elm.tail = None
        if not elm.text or len(elm) and elm.text.isspace():
            elm.text = None


def remove_newlines_in_xml_text(node: Element) -> None:
    """Remove newlines in the text of leaf XML elements."""
    for elm in node.iter():
        if not len(elm) and elm.text is not None and '\n' in elm.text:
            elm.text = elm.text.replace('\n', '')


def sign_xml_node(node: Element, key_file: str, cert_file: str, signature_method: str, digest_method: str) -> None:
    """
    Sign a XML element and insert the signature as the first child element.

    :param node: The XML element to sign
    :param key_file: The path to a key file.
    :param cert_file: The path to a certificate file.
    :param signature_method: XMLSEC signature method, e.g., 'RSA_SHA1', 'RSA_SHA256', 'RSA_SHA512'.
    :param digest_method: XMLSEC digest method, e.g., 'SHA1', 'SHA256', 'SHA512'.
    """
    # Prepare signature template for xmlsec to fill it with the signature and additional data
    ctx = xmlsec.SignatureContext()
    signature = xmlsec.template.create(node, xmlsec.Transform.EXCL_C14N, getattr(xmlsec.Transform, signature_method))
    key_info = xmlsec.template.ensure_key_info(signature)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_certificate(x509_data)
    xmlsec.template.x509_data_add_issuer_serial(x509_data)

    # Ensure the target node has an ID attribute and get its value.
    node_id = node.get(XML_ATTRIBUTE_ID)
    if not node_id:
        node_id = create_xml_uuid()
        node.set(XML_ATTRIBUTE_ID, node_id)

    # Unlike HTML, XML doesn't have a single standardized id so we need to tell xmlsec about our id.
    ctx.register_id(node, XML_ATTRIBUTE_ID, None)

    # Add reference to signature with URI attribute pointing to that ID.
    ref = xmlsec.template.add_reference(signature, getattr(xmlsec.Transform, digest_method), uri="#" + node_id)

    # XML normalization transform performed on the node contents before signing and verification.
    # 1. When enveloped signature method is used, the signature is included as a child of the signed element.
    #    The signature is removed from the document before signing/verification.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    # 2. This ensures that changes to irrelevant whitespace, attribute ordering, etc. won't invalidate the signature.
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

    # xmlsec library adds unnecessary newlines to the signature template. They may cause troubles to other
    # XMLSEC implementations, so we remove any unnecessary whitespace to avoid compatibility issues.
    for elm in signature.iter():
        if elm.text is not None and '\n' in elm.text:
            elm.text = elm.text.replace('\n', '')
        if elm.tail is not None and '\n' in elm.tail:
            elm.tail = elm.tail.replace('\n', '')
    remove_extra_xml_whitespace(signature)

    # Create the signature as the first child element.
    node.insert(0, signature)
    ctx.key = xmlsec.Key.from_file(key_file, xmlsec.constants.KeyDataFormatPem)
    ctx.key.load_cert_from_file(cert_file, xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature)

    # xmlsec library adds unnecessary tail newlines again, so we remove them.
    remove_extra_xml_whitespace(signature)
