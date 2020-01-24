"""XML utility functions."""
import re
from collections import namedtuple
from io import BytesIO
from typing import BinaryIO, List, Union
from uuid import uuid4

import xmlsec
from lxml import etree
from lxml.etree import Element, ElementTree, QName

from eidas_node.errors import SecurityError

VALID_XML_ID_RE = re.compile('^[_a-zA-Z][-._a-zA-Z0-9]*$')
XML_ENC_NAMESPACE = 'http://www.w3.org/2001/04/xmlenc#'
XML_SIG_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
XML_ATTRIBUTE_ID = 'ID'
XML_ATTRIBUTE_URI = 'URI'

SignatureInfo = namedtuple('SignatureInfo', 'signature,references')


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


def decrypt_xml(tree: ElementTree, key_file: str) -> int:
    """
    Decrypt a XML document.

    :param tree: The XML document to decrypt.
    :param key_file: A path to an encryption key file.
    :return: The number of decrypted elements
    """
    encrypted_elements = tree.findall(".//{%s}EncryptedData" % XML_ENC_NAMESPACE)
    if encrypted_elements:
        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(key_file, xmlsec.constants.KeyDataFormatPem))
        enc_ctx = xmlsec.EncryptionContext(manager)
        for elm in encrypted_elements:
            enc_ctx.decrypt(elm)

        remove_extra_xml_whitespace(tree.getroot())
    return len(encrypted_elements)


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


def sign_xml_node(node: Element, key_file: str, cert_file: str,
                  signature_method: str, digest_method: str, position: int = 0) -> None:
    """
    Sign a XML element and insert the signature as a child element.

    :param node: The XML element to sign
    :param key_file: The path to a key file.
    :param cert_file: The path to a certificate file.
    :param signature_method: XMLSEC signature method, e.g., 'RSA_SHA1', 'RSA_SHA256', 'RSA_SHA512'.
    :param digest_method: XMLSEC digest method, e.g., 'SHA1', 'SHA256', 'SHA512'.
    :param position: The position of the signature.
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

    # Insert the signature as a child element.
    node.insert(position, signature)
    ctx.key = xmlsec.Key.from_file(key_file, xmlsec.constants.KeyDataFormatPem)
    ctx.key.load_cert_from_file(cert_file, xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature)

    # xmlsec library adds unnecessary tail newlines again, so we remove them.
    remove_extra_xml_whitespace(signature)


def verify_xml_signatures(node: Element, cert_file: str) -> List[SignatureInfo]:
    """
    Verify all XML signatures from the provided node.

    :param node: A XML subtree.
    :param cert_file: A path to the certificate file.
    :return: A list of signature details if there are any signatures, an empty list otherwise.
    :raise SecurityError: If any of the element references or signatures are invalid.
    """
    signature_info = []
    signatures = node.findall(".//{}".format(QName(XML_SIG_NAMESPACE, 'Signature')))
    if signatures:
        key = xmlsec.Key.from_file(cert_file, xmlsec.constants.KeyDataFormatCertPem)
        for sig_num, signature in enumerate(signatures, 1):
            # Find and register referenced elements
            referenced_elements = []
            ctx = xmlsec.SignatureContext()
            refs = signature.findall('./{}/{}'.format(QName(XML_SIG_NAMESPACE, 'SignedInfo'),
                                                      QName(XML_SIG_NAMESPACE, 'Reference')))
            for ref_num, ref in enumerate(refs, 1):
                # ID is referenced in the URI attribute and prefixed with a hash.
                ref_id = ref.get(XML_ATTRIBUTE_URI)
                if ref_id is None or len(ref_id) < 2 or ref_id[0] != '#':
                    raise SecurityError('Signature {}, reference {}: Invalid id {!r}.'
                                        .format(sig_num, ref_num, ref_id))
                ref_id = ref_id[1:]
                ref_elms = node.xpath('//*[@{}=\'{}\']'.format(XML_ATTRIBUTE_ID, ref_id))
                if not ref_elms:
                    raise SecurityError('Signature {}, reference {}: Element with id {!r} not found.'
                                        .format(sig_num, ref_num, ref_id))
                if len(ref_elms) > 1:
                    raise SecurityError('Signature {}, reference {}: Element with id {!r} occurs more than once.'
                                        .format(sig_num, ref_num, ref_id))
                referenced_elements.append(ref_elms[0])
                # Unlike HTML, XML doesn't have a single standardized id so we need to tell xmlsec about our id.
                ctx.register_id(ref_elms[0], XML_ATTRIBUTE_ID, None)

            # Verify the signature
            try:
                ctx.key = key
                ctx.verify(signature)
            except xmlsec.Error:
                raise SecurityError('Signature {} is invalid.'.format(sig_num))

            signature_info.append(SignatureInfo(signature, tuple(referenced_elements)))
    return signature_info
