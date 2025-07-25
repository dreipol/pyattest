from asn1crypto import pem
from asn1crypto.x509 import Certificate


def _load_certificate(cert_bytes: bytes) -> Certificate:
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)

    return Certificate.load(cert_bytes)
