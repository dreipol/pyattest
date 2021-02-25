import datetime

from cryptography import x509, utils
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

key_usage = x509.KeyUsage(
    True,  # digital_signature
    False,  # content_commitment
    False,  # key_encipherment
    False,  # data_encipherment
    False,  # key_agreement
    True,  # key_cert_sign
    True,  # crl_sign
    False,  # encipher_only
    False  # decipher_only
)


def generate():
    """ Generate root and intermediate certificates for the apple attestation. """
    root_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, )

    with open('tests/fixtures/root_key.pem', 'wb') as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b'123'),
        ))

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'pyattest-testing-ca')])
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(root_private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
        .add_extension(key_usage, critical=False) \
        .sign(root_private_key, hashes.SHA256())

    with open('tests/fixtures/root_cert.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
