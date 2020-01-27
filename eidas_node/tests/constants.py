from pathlib import Path

from eidas_node.constants import XmlBlockCipher, XmlKeyTransport

DATA_DIR = Path(__file__).parent / 'data'  # type: Path
KEY_FILE = str(DATA_DIR / 'key.pem')
CERT_FILE = str(DATA_DIR / 'cert.pem')
NIA_CERT_FILE = str(DATA_DIR / 'nia-test-cert.pem')
WRONG_KEY_FILE = str(DATA_DIR / 'wrong-key.pem')
WRONG_CERT_FILE = str(DATA_DIR / 'wrong-cert.pem')

SIGNATURE_OPTIONS = {
    'key_file': KEY_FILE,
    'cert_file': CERT_FILE,
    'signature_method': 'RSA_SHA1',
    'digest_method': 'SHA1',
}

ENCRYPTION_OPTIONS = {
    'cert_file': CERT_FILE,
    'encryption_method': XmlBlockCipher.AES128_CBC,
    'key_transport': XmlKeyTransport.RSA_OAEP_MGF1P,
}
