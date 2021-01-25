import datetime
import struct
from hashlib import sha256
from pathlib import Path

from cbor2 import dumps as cbor_encode
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.base import Encoding, load_pem_private_key
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from tests.generate_certificates import generate


def create(app_id: str, nonce: bytes, aaguid: bytes, counter: int):
    """ Helper to create a fake apple attestation. """
    # needs: AppId, nonce, aaguid, counter
    # generate()
    # return

    # pyattest-testing
    root_key = load_pem_private_key(Path('stubs/root.key').read_bytes(), None)
    root_cert = load_pem_x509_certificate(Path('fixtures/root.crt').read_bytes())

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'pyattest-testing-leaf')])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'pyattest-testing')])

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(root_cert.subject) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
        .sign(root_key, hashes.SHA256())

    # create cert, signed with the intermediate.key -> add all 3 certs to x5c

    foo = {
        'fmt': 'apple-appattest',
        'attStmt': {
            'x5c': [
                cert.public_bytes(serialization.Encoding.DER),
                intermediate_cert.public_bytes(serialization.Encoding.DER),
                root_cert.public_bytes(serialization.Encoding.DER),
            ],
            'receipt': b'',
        },
        'authData': sha256(app_id.encode()).digest()
                    + b'\x00'  # Flag, we'll fill it with zero
                    + struct.pack('!I', counter)
                    + aaguid  # TODO: Fillup to ensure 16 bytes
                    + struct.pack('!H', 32)  # Our sha256 digest is always 32bytes
                    + sha256(cert.public_bytes(serialization.Encoding.DER)).digest()
        ,
    }

    # add sha256digest of public key

    # return atteastation, public key, cbor encoded
    return cbor_encode(foo)
