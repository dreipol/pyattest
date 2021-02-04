import base64
import datetime
import struct
from hashlib import sha256
from pathlib import Path

import jwt
from asn1crypto.core import OctetString
from cbor2 import dumps as cbor_encode
from cryptography import x509
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key, NoEncryption
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import NameOID

from tests.factories.certificates import key_usage


def google(apk_package_name: str, nonce: bytes, basic_integrity: bool = True, cts_profile: bool = True,
           apk_cert_digest: bytes = None):
    """ Helper to create a fake google attestation. """
    root_key = load_pem_private_key(Path('tests/fixtures/root_key.pem').read_bytes(), b'123')
    root_cert = load_pem_x509_certificate(Path('tests/fixtures/root_cert.pem').read_bytes())
    apk_cert_digest = apk_cert_digest or b'foobar'

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'pyattest-testing-leaf')])
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(root_cert.subject) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
        .add_extension(key_usage, critical=False) \
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('pyattest-testing-leaf.ch')]), critical=False) \
        .sign(root_key, hashes.SHA256())

    data = {
        'timestampMs': 9860437986543,
        'nonce': base64.b64encode(nonce).decode(),
        'apkPackageName': apk_package_name,
        'apkCertificateDigestSha256': [base64.b64encode(apk_cert_digest).decode()],
        'ctsProfileMatch': cts_profile,
        'basicIntegrity': basic_integrity,
        'evaluationType': 'BASIC'
    }

    headers = {'x5c': [
        cert.public_bytes(serialization.Encoding.PEM).decode().replace('-----BEGIN CERTIFICATE-----\n', '').replace(
            '\n-----END CERTIFICATE-----\n', ''),
        root_cert.public_bytes(serialization.Encoding.PEM).decode().replace('-----BEGIN CERTIFICATE-----\n',
                                                                            '').replace('\n-----END CERTIFICATE-----\n',
                                                                                        ''),
    ]}

    return jwt.encode(data, private_key, algorithm='RS256', headers=headers), apk_cert_digest


def apple(app_id: str, nonce: bytes, aaguid: bytes = b'appattestdevelop', counter: int = 0,
          wrong_public_key: bool = False):
    """ Helper to create a fake apple attestation. """
    root_key = load_pem_private_key(Path('tests/fixtures/root_key.pem').read_bytes(), b'123')
    root_cert = load_pem_x509_certificate(Path('tests/fixtures/root_cert.pem').read_bytes())

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.DER,
                                                       format=serialization.PublicFormat.PKCS1)

    auth_data_public_key = public_key if not wrong_public_key else 'XXXXX'.encode()

    auth_data = (sha256(app_id.encode()).digest()
                 + b'\x00'  # Flag, we'll fill it with zero
                 + struct.pack('!I', counter)
                 + aaguid  # TODO: Fillup to ensure 16 bytes
                 + struct.pack('!H', 32)  # Our sha256 digest is always 32bytes
                 + sha256(auth_data_public_key).digest())

    nonce = sha256(auth_data + sha256(nonce).digest())

    # When comparing this nonce with the one calculated on the server, we'll strip 6 bytes which are normally
    # used to indicated an ASN1 envelope sequence. See the verify_nonce method in the apple verifier.
    der_nonce = bytes(6) + OctetString(nonce.digest()).native

    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'pyattest-testing-leaf')])
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(root_cert.subject) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
        .add_extension(key_usage, critical=False) \
        .add_extension(UnrecognizedExtension(ObjectIdentifier('1.2.840.113635.100.8.2'), der_nonce), critical=False) \
        .sign(root_key, hashes.SHA256())

    data = {
        'fmt': 'apple-appattest',
        'attStmt': {
            'x5c': [
                cert.public_bytes(serialization.Encoding.DER),
                root_cert.public_bytes(serialization.Encoding.DER),
            ],
            'receipt': b'',
        },
        'authData': auth_data,
    }

    return cbor_encode(data), public_key
