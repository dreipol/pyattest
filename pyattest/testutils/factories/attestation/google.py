import base64
import datetime
import os
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from jose import jwe, jws
from jose.constants import ALGORITHMS

from pyattest.testutils.factories.certificates import key_usage


def get_play_integrity_api_attestation(
    apk_package_name: str,
    nonce: bytes,
    app_integrity_verdict: str,
    device_integrity_verdict: [str],
):
    """Helper to create a fake google attestation."""
    root_key = ec.generate_private_key(ec.SECP256K1())
    aes_key = os.urandom(32)
    payload = {
        "requestDetails": {
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
            "requestPackageName": apk_package_name,
        },
        "appIntegrity": {
            "appRecognitionVerdict": app_integrity_verdict,
            "packageName": apk_package_name,
            "certificateSha256Digest": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": device_integrity_verdict,
        },
    }
    jws_token = jws.sign(payload, root_key, algorithm=ALGORITHMS.ES256)
    return (
        jwe.encrypt(
            jws_token,
            aes_key,
            algorithm=ALGORITHMS.A256KW,
            encryption=ALGORITHMS.A256GCM,
        ),
        root_key.public_key(),
        aes_key,
    )


def get(
    apk_package_name: str,
    nonce: bytes,
    basic_integrity: bool = True,
    cts_profile: bool = True,
    apk_cert_digest: bytes = None,
):
    """Helper to create a fake google attestation."""
    here = os.path.abspath(os.path.dirname(__file__))
    fixtures = os.path.join(here, "..", "..", "fixtures")

    root_key = load_pem_private_key(
        Path(f"{fixtures}/root_key.pem").read_bytes(), b"123"
    )
    root_cert = load_pem_x509_certificate(
        Path(f"{fixtures}/root_cert.pem").read_bytes()
    )

    apk_cert_digest = apk_cert_digest or b"foobar"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pyattest-testing-leaf")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("pyattest-testing-leaf.ch")]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    data = {
        "timestampMs": 9860437986543,
        "nonce": base64.b64encode(nonce).decode(),
        "apkPackageName": apk_package_name,
        "apkCertificateDigestSha256": [base64.b64encode(apk_cert_digest).decode()],
        "ctsProfileMatch": cts_profile,
        "basicIntegrity": basic_integrity,
        "evaluationType": "BASIC",
    }

    headers = {
        "x5c": [
            cert.public_bytes(serialization.Encoding.PEM)
            .decode()
            .replace("-----BEGIN CERTIFICATE-----\n", "")
            .replace("\n-----END CERTIFICATE-----\n", ""),
            root_cert.public_bytes(serialization.Encoding.PEM)
            .decode()
            .replace("-----BEGIN CERTIFICATE-----\n", "")
            .replace("\n-----END CERTIFICATE-----\n", ""),
        ]
    }

    return (
        jwt.encode(data, private_key, algorithm="RS256", headers=headers),
        apk_cert_digest,
    )
