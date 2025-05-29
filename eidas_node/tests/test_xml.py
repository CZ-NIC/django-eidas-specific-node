import re
from io import BytesIO
from typing import BinaryIO, Optional, Set, TextIO, cast
from unittest.mock import Mock, patch

import xmlsec
from django.test import SimpleTestCase
from lxml.etree import Element, ElementTree, QName, SubElement

from eidas_node.constants import XmlBlockCipher, XmlKeyTransport
from eidas_node.errors import SecurityError
from eidas_node.saml import EIDAS_NAMESPACES, Q_NAMES
from eidas_node.tests.constants import (
    CERT_FILE,
    DATA_DIR,
    KEY_LOCATION,
    KEY_SOURCE,
    NIA_CERT_FILE,
    SIGNATURE_OPTIONS,
    WRONG_KEY_LOCATION,
)
from eidas_node.xml import (
    XML_SIG_NAMESPACE,
    XmlKeyInfo,
    create_xml_uuid,
    decrypt_xml,
    dump_xml,
    encrypt_xml_node,
    get_element_path,
    is_xml_id_valid,
    parse_xml,
    remove_extra_xml_whitespace,
    remove_newlines_in_xml_text,
    sign_xml_node,
    verify_xml_signatures,
)

# This is an ugly hack but only for unit tests...
# TODO: Remove when we drop support for libxmlsec1 < 1.2.27
LIBXMLSEC_VERSION = tuple(map(int, re.search(r"\((\d+)\.(\d+)\.(\d+)\)", xmlsec.__doc__).groups()))  # type: ignore


class TestGetElementPath(SimpleTestCase):
    def test_parse_xml_data_types(self):
        binary = b"<lightRequest></lightRequest>"
        parse_xml(binary)
        parse_xml(binary.decode("ascii"))
        parse_xml(BytesIO(binary))

    def test_get_element_path_without_namespaces(self):
        root = Element("root")
        grandchild = SubElement(SubElement(root, "child"), "grandchild")
        self.assertEqual(get_element_path(root), "<root>")
        self.assertEqual(get_element_path(grandchild), "<root><child><grandchild>")

    def test_get_element_path_with_namespaces(self):
        root = Element(Q_NAMES["saml2p:Response"], nsmap=EIDAS_NAMESPACES)
        leaf = SubElement(root, Q_NAMES["saml2:EncryptedAssertion"])
        self.assertEqual(get_element_path(root), "<saml2p:Response>")
        self.assertEqual(get_element_path(leaf), "<saml2p:Response><saml2:EncryptedAssertion>")

    def test_get_element_path_mixed(self):
        root = Element(Q_NAMES["saml2p:Response"], nsmap=EIDAS_NAMESPACES)
        leaf = SubElement(SubElement(root, Q_NAMES["saml2:EncryptedAssertion"]), "wrong")
        self.assertEqual(get_element_path(root), "<saml2p:Response>")
        self.assertEqual(get_element_path(leaf), "<saml2p:Response><saml2:EncryptedAssertion><wrong>")


class TestValidXMLID(SimpleTestCase):
    def test_is_xml_id_valid_success(self):
        for value in "aA5", "a.5", "a-5", "_5":
            self.assertTrue(is_xml_id_valid(value))

    def test_is_xml_id_valid_failure(self):
        for value in "0a", ".a", "-a", "#a", "a#", "a:a":
            self.assertFalse(is_xml_id_valid(value))

    @patch("eidas_node.xml.uuid4", return_value="0uuid4")
    def test_create_xml_uuid_default_prefix(self, _uuid_mock: Mock):
        self.assertEqual(create_xml_uuid(), "_0uuid4")

    @patch("eidas_node.xml.uuid4", return_value="0uuid4")
    def test_create_xml_uuid_valid_prefix(self, _uuid_mock: Mock):
        self.assertEqual(create_xml_uuid("T"), "T0uuid4")

    @patch("eidas_node.xml.uuid4", return_value="0uuid4")
    def test_create_xml_uuid_invalid_prefix(self, _uuid_mock: Mock):
        for prefix in "", "-", "#":
            self.assertRaisesMessage(ValueError, "Invalid prefix", create_xml_uuid, prefix)


class TestDecryptXML(SimpleTestCase):
    def test_decrypt_xml_with_document_not_encrypted(self):
        with cast(BinaryIO, (DATA_DIR / "saml_response.xml").open("rb")) as f:
            document = parse_xml(f.read())
        expected = dump_xml(document).decode("utf-8")
        self.assertEqual(decrypt_xml(document, KEY_SOURCE, KEY_LOCATION), 0)
        actual = dump_xml(document).decode("utf-8")
        self.assertXMLEqual(expected, actual)

    def test_decrypt_xml_with_document_encrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / "saml_response_decrypted.xml").open("rb")) as f:
            document_decrypted = parse_xml(f.read())
        with cast(BinaryIO, (DATA_DIR / "saml_response_encrypted.xml").open("rb")) as f:
            document_encrypted = parse_xml(f.read())
        expected = dump_xml(document_decrypted).decode("utf-8")
        self.assertEqual(decrypt_xml(document_encrypted, KEY_SOURCE, KEY_LOCATION), 1)
        actual = dump_xml(document_encrypted).decode("utf-8")
        self.assertXMLEqual(expected, actual)

    def test_decrypt_xml_with_document_encrypted_wrong_key(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / "saml_response_encrypted.xml").open("rb")) as f:
            document_encrypted = parse_xml(f.read())
        self.assertRaises(xmlsec.Error, decrypt_xml, document_encrypted, KEY_SOURCE, WRONG_KEY_LOCATION)

    def test_decrypt_xml_with_document_decrypted(self):
        self.maxDiff = None
        with cast(BinaryIO, (DATA_DIR / "saml_response_decrypted.xml").open("rb")) as f:
            document_decrypted = parse_xml(f.read())
        expected = dump_xml(document_decrypted).decode("utf-8")
        self.assertEqual(decrypt_xml(document_decrypted, KEY_SOURCE, KEY_LOCATION), 0)
        actual = dump_xml(document_decrypted).decode("utf-8")
        self.assertXMLEqual(expected, actual)

    def test_wrong_key_source(self):
        with cast(BinaryIO, (DATA_DIR / "saml_response_encrypted.xml").open("rb")) as f:
            document_encrypted = parse_xml(f.read())
        self.assertRaises(RuntimeError, decrypt_xml, document_encrypted, "non-existent-source", KEY_LOCATION)


class TestRemoveExtraWhitespace(SimpleTestCase):
    def create_tree(self, text: Optional[str]) -> tuple:
        root = Element("root")
        root.text = text
        root.tail = text
        child = SubElement(root, "child")
        child.text = text
        child.tail = text
        grandchild = SubElement(child, "child")
        grandchild.text = text
        grandchild.tail = text
        return root, child, grandchild

    def test_remove_extra_xml_whitespace_various_whitespace(self):
        for space in None, "", " ", " \n\t":
            with self.subTest(space=space):
                root, child, grandchild = self.create_tree(space)
                grandchild.text = None
                remove_extra_xml_whitespace(root)
                self.assertIsNone(root.text)
                self.assertIsNone(root.tail)
                self.assertIsNone(child.text)
                self.assertIsNone(child.tail)
                self.assertIsNone(grandchild.text)
                self.assertIsNone(grandchild.tail)

    def test_remove_extra_xml_whitespace_leaf_node_text_empty(self):
        for text in None, "":
            with self.subTest(text=text):
                root, child, grandchild = self.create_tree(" ")
                grandchild.text = text
                remove_extra_xml_whitespace(root)
                self.assertIsNone(root.text)
                self.assertIsNone(root.tail)
                self.assertIsNone(child.text)
                self.assertIsNone(child.tail)
                self.assertIsNone(grandchild.text)
                self.assertIsNone(grandchild.tail)

    def test_remove_extra_xml_whitespace_leaf_node_whitespace_text_preserved(self):
        for text in " ", " \t\n":
            with self.subTest(text=text):
                root, child, grandchild = self.create_tree(" ")
                grandchild.text = text
                remove_extra_xml_whitespace(root)
                self.assertIsNone(root.text)
                self.assertIsNone(root.tail)
                self.assertIsNone(child.text)
                self.assertIsNone(child.tail)
                self.assertEqual(grandchild.text, text)
                self.assertIsNone(grandchild.tail)

    def test_remove_extra_xml_whitespace_text_preserved(self):
        for text in " abc", "abc":
            with self.subTest(text=text):
                root, child, grandchild = self.create_tree(text)
                remove_extra_xml_whitespace(root)
                self.assertEqual(root.text, text)
                self.assertEqual(root.tail, text)
                self.assertEqual(child.text, text)
                self.assertEqual(child.tail, text)
                self.assertEqual(grandchild.text, text)
                self.assertEqual(grandchild.tail, text)


class TestRemoveNewlinesInXMLText(SimpleTestCase):
    def test_remove_newlines_in_xml_text_only_leaf_nodes(self):
        text_with_newlines = "\nhello \nword\n"
        text_without_newlines = "hello word"
        root = Element("root")
        root.text = text_with_newlines
        child = SubElement(root, "child")
        child.text = text_with_newlines
        child2 = SubElement(root, "child")
        child2.text = text_with_newlines
        grandchild = SubElement(child2, "child")
        grandchild.text = text_with_newlines
        remove_newlines_in_xml_text(root)
        self.assertEqual(root.text, text_with_newlines)
        self.assertEqual(child.text, text_without_newlines)
        self.assertEqual(child2.text, text_with_newlines)
        self.assertEqual(grandchild.text, text_without_newlines)

    def test_remove_newlines_in_xml_text_none(self):
        root = Element("root")
        remove_newlines_in_xml_text(root)
        self.assertIsNone(root.text)


class TestSignXMLNode(SimpleTestCase):
    USED_NAMESPACES = {"saml2": EIDAS_NAMESPACES["saml2"], "saml2p": EIDAS_NAMESPACES["saml2p"]}

    @patch("eidas_node.xml.create_xml_uuid", return_value="id-0uuid4")
    def test_sign_xml_node_without_id(self, uuid_mock):
        self.maxDiff = None
        root = Element(Q_NAMES["saml2p:Response"], nsmap=self.USED_NAMESPACES)
        assertion = SubElement(root, Q_NAMES["saml2:Assertion"])
        SubElement(assertion, Q_NAMES["saml2:Issuer"]).text = "Test Issuer"
        sign_xml_node(root, position=0, **SIGNATURE_OPTIONS)

        if LIBXMLSEC_VERSION < (1, 2, 35):  # pragma: no cover
            filename = "signed_response.xml"
        else:  # pragma: no cover
            filename = "signed_response_1.2.35.xml"
        with cast(TextIO, (DATA_DIR / filename).open("r")) as f:
            self.assertXMLEqual(dump_xml(root).decode("utf-8"), f.read())

    def test_sign_xml_node_with_id(self):
        self.maxDiff = None
        root = Element(Q_NAMES["saml2p:Response"], {"ID": "id-0uuid4"}, nsmap=self.USED_NAMESPACES)
        assertion = SubElement(root, Q_NAMES["saml2:Assertion"])
        SubElement(assertion, Q_NAMES["saml2:Issuer"]).text = "Test Issuer"
        sign_xml_node(root, position=0, **SIGNATURE_OPTIONS)

        if LIBXMLSEC_VERSION < (1, 2, 35):  # pragma: no cover
            filename = "signed_response.xml"
        else:  # pragma: no cover
            filename = "signed_response_1.2.35.xml"
        with cast(TextIO, (DATA_DIR / filename).open("r")) as f:
            self.assertXMLEqual(dump_xml(root).decode("utf-8"), f.read())

    @patch("eidas_node.xml.create_xml_uuid", return_value="id-0uuid4")
    def test_sign_xml_node_multiple(self, uuid_mock):
        self.maxDiff = None
        root = Element(Q_NAMES["saml2p:Response"], {"ID": "id-response"}, nsmap=self.USED_NAMESPACES)
        assertion = SubElement(root, Q_NAMES["saml2:Assertion"])
        SubElement(assertion, Q_NAMES["saml2:Issuer"]).text = "Test Issuer"
        sign_xml_node(assertion, position=0, **SIGNATURE_OPTIONS)
        sign_xml_node(root, position=0, **SIGNATURE_OPTIONS)

        if LIBXMLSEC_VERSION < (1, 2, 35):  # pragma: no cover
            filename = "signed_response_and_assertion.xml"
        else:  # pragma: no cover
            filename = "signed_response_and_assertion.xml_1.2.35.xml"
        with cast(TextIO, (DATA_DIR / filename).open("r")) as f:
            self.assertXMLEqual(dump_xml(root).decode("utf-8"), f.read())

    @patch.dict(
        "eidas_node.tests.constants.SIGNATURE_OPTIONS",
        {
            "key_source": "non-existent-source",
        },
    )
    def test_wrong_key_source(self):
        root = Element(Q_NAMES["saml2p:Response"], {"ID": "id-0uuid4"}, nsmap=self.USED_NAMESPACES)
        with self.assertRaises(RuntimeError):
            sign_xml_node(root, position=0, **SIGNATURE_OPTIONS)


class TestVerifyXMLSignatures(SimpleTestCase):
    def test_verify_xml_signatures_no_signatures(self):
        root = Element("root")
        self.assertEqual(verify_xml_signatures(root, CERT_FILE), [])

    def test_verify_xml_signatures_success(self):
        with cast(TextIO, (DATA_DIR / "signed_response.xml").open("r")) as f:
            tree = parse_xml(f.read())

        remove_extra_xml_whitespace(tree)  # Reverts pretty printing applied after signing
        verify_xml_signatures(tree, CERT_FILE)

    def test_verify_xml_signatures_nia(self):
        with cast(TextIO, (DATA_DIR / "nia_test_response.xml").open("r")) as f:
            tree = parse_xml(f.read())

        remove_extra_xml_whitespace(tree)
        verify_xml_signatures(tree, NIA_CERT_FILE)

    def test_verify_xml_signatures_fail(self):
        with cast(TextIO, (DATA_DIR / "signed_response.xml").open("r")) as f:
            tree = parse_xml(f.read())

        # Fails because of pretty printing
        self.assertRaises(SecurityError, verify_xml_signatures, tree, CERT_FILE)

    def test_verify_xml_signatures_ref_not_found(self):
        root = Element("root")
        signature = SubElement(root, QName(XML_SIG_NAMESPACE, "Signature"))
        info = SubElement(signature, QName(XML_SIG_NAMESPACE, "SignedInfo"))
        SubElement(info, QName(XML_SIG_NAMESPACE, "Reference"), {"URI": "#id"})
        with self.assertRaisesMessage(SecurityError, "Signature 1, reference 1: Element with id 'id' not found."):
            verify_xml_signatures(root, CERT_FILE)

    def test_verify_xml_signatures_ref_not_once(self):
        root = Element("root")
        signature = SubElement(root, QName(XML_SIG_NAMESPACE, "Signature"))
        info = SubElement(signature, QName(XML_SIG_NAMESPACE, "SignedInfo"))
        SubElement(info, QName(XML_SIG_NAMESPACE, "Reference"), {"URI": "#id"})
        SubElement(root, "item", {"ID": "id"})
        SubElement(root, "item2", {"ID": "id"})
        msg = "Signature 1, reference 1: Element with id 'id' occurs more than once."
        self.assertRaisesMessage(SecurityError, msg, verify_xml_signatures, root, CERT_FILE)

    def test_verify_xml_signatures_ref_invalid(self):
        for id_ in "", "id", "#":
            with self.subTest(id=id_):
                root = Element("root")
                signature = SubElement(root, QName(XML_SIG_NAMESPACE, "Signature"))
                info = SubElement(signature, QName(XML_SIG_NAMESPACE, "SignedInfo"))
                SubElement(info, QName(XML_SIG_NAMESPACE, "Reference"), {"URI": id_})
                msg = "Signature 1, reference 1: Invalid id '{}'.".format(id_)
                self.assertRaisesMessage(SecurityError, msg, verify_xml_signatures, root, CERT_FILE)


class TestEncryptXMLNode(SimpleTestCase):
    def test_encrypt_xml_node(self):
        supported_ciphers: Set[XmlBlockCipher] = set(XmlBlockCipher)
        if LIBXMLSEC_VERSION < (1, 2, 27):  # pragma: no cover
            supported_ciphers -= {XmlBlockCipher.AES128_GCM, XmlBlockCipher.AES192_GCM, XmlBlockCipher.AES256_GCM}

        for cipher in supported_ciphers:
            with cast(BinaryIO, (DATA_DIR / "saml_response_decrypted.xml").open("rb")) as f:
                document = parse_xml(f.read())
            remove_extra_xml_whitespace(document.getroot())
            original = dump_xml(document).decode()

            # Encrypt <Assertion>
            assertion = document.find(".//{}".format(Q_NAMES["saml2:Assertion"]))
            encrypt_xml_node(assertion, CERT_FILE, cipher, XmlKeyTransport.RSA_OAEP_MGF1P)

            # <Assertion> replaced with <EncryptedData>
            self.assertIsNone(document.find(".//{}".format(Q_NAMES["saml2:Assertion"])))
            enc_data = document.find(
                ".//{}/{}".format(Q_NAMES["saml2:EncryptedAssertion"], Q_NAMES["xmlenc:EncryptedData"])
            )
            self.assertIsNotNone(enc_data)
            self.assertEqual(enc_data[0].get("Algorithm"), cipher.value)

            # Verify that the original and decrypted document match.
            self.assertEqual(decrypt_xml(document, KEY_SOURCE, KEY_LOCATION), 1)
            decrypted = dump_xml(document).decode()
            self.assertEqual(original, decrypted)

    @patch.dict(
        "eidas_node.xml.XML_KEY_INFO", {XmlBlockCipher.TRIPLEDES_CBC: XmlKeyInfo(xmlsec.constants.KeyDataAes, 192)}
    )
    def test_encrypt_xml_node_failure_wrong_key_type(self):
        root = Element("root")
        data = SubElement(root, "data")
        with self.assertRaisesMessage(SecurityError, "Invalid certificate, invalid or unsupported encryption method"):
            encrypt_xml_node(data, CERT_FILE, XmlBlockCipher.TRIPLEDES_CBC, XmlKeyTransport.RSA_OAEP_MGF1P)

    def test_encrypt_xml_node_namespaces_declared(self):
        root = Element(
            Q_NAMES["saml2p:Response"],
            nsmap={
                "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
                "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",  # Not used in encrypted data
            },
        )

        # Create an encrypted document
        encrypted_assertion = SubElement(root, Q_NAMES["saml2:EncryptedAssertion"])
        assertion = SubElement(encrypted_assertion, Q_NAMES["saml2:Assertion"])
        SubElement(assertion, Q_NAMES["saml2:Issuer"]).text = "CZ.NIC"
        encrypt_xml_node(assertion, CERT_FILE, XmlBlockCipher.AES128_CBC, XmlKeyTransport.RSA_OAEP_MGF1P)

        # Transfer the encrypted data to a document with no namespaces
        container = Element("container")
        container.append(encrypted_assertion[0])
        document = ElementTree(container)

        # If the decrypted element doesn't declare all necessary namespaces, no exception is raised, but
        # an error such as `namespace error : Namespace prefix saml2 on Assertion is not defined` is printed.
        # We need to check the namespace maps.
        self.assertEqual(decrypt_xml(document, KEY_SOURCE, KEY_LOCATION), 1)
        self.assertEqual(container.nsmap, {})
        self.assertEqual(container[0].nsmap, {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"})
