"""Do the same tests for signing and decrypting XML as in test_xml.py, but now with HSM setup and settings."""

from unittest.mock import patch

from eidas_node.tests import test_xml


def setUpModule():
    from eidas_node.tests import softhsm_setup

    softhsm_setup.setup()


def tearDownModule():
    from eidas_node.tests import softhsm_setup

    softhsm_setup.teardown()


@patch.dict(
    "eidas_node.tests.test_xml.SIGNATURE_OPTIONS",
    {
        "key_source": "engine",
        "key_location": "pkcs11;pkcs11:token=test;object=test;pin-value=secret1",
    },
)
class TestSignXMLNodePKCS11(test_xml.TestSignXMLNode):
    """Sign tests with key stored in SoftHSM."""


# Commented out as underlying libraries doesn't support decrypt RSA-OAEP algorithm for now
# @patch('eidas_node.tests.test_xml.KEY_SOURCE', 'engine')
# @patch('eidas_node.tests.test_xml.KEY_LOCATION', 'pkcs11;pkcs11:token=test;object=test;pin-value=secret1')
# class TestDecryptXMLPKCS11(test_xml.TestDecryptXML):
#     "Decrypt tests with key stored in SoftHSM"
