from pathlib import Path

from eidas_node.constants import XmlBlockCipher, XmlKeyTransport

DATA_DIR: Path = Path(__file__).parent / 'data'
KEY_SOURCE = 'file'
KEY_LOCATION = str(DATA_DIR / 'key.pem')
CERT_FILE = str(DATA_DIR / 'cert.pem')
NIA_CERT_FILE = str(DATA_DIR / 'nia-test-cert.pem')
WRONG_KEY_LOCATION = str(DATA_DIR / 'wrong-key.pem')
WRONG_CERT_FILE = str(DATA_DIR / 'wrong-cert.pem')

SIGNATURE_OPTIONS = {
    'key_source': KEY_SOURCE,
    'key_location': KEY_LOCATION,
    'cert_file': CERT_FILE,
    'signature_method': 'RSA_SHA1',
    'digest_method': 'SHA1',
}

ENCRYPTION_OPTIONS = {
    'cert_file': CERT_FILE,
    'encryption_method': XmlBlockCipher.AES128_CBC,
    'key_transport': XmlKeyTransport.RSA_OAEP_MGF1P,
}

AUXILIARY_STORAGE = {
    'BACKEND': 'eidas_node.storage.ignite.AuxiliaryIgniteStorage',
    'OPTIONS': {
        'host': 'test.example.net',
        'port': 1234,
        'cache_name': 'aux-cache',
        'prefix': 'aux-',
        'timeout': 66,
    }
}
