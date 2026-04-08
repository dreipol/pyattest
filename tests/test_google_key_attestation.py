"""Tests for GoogleKeyAttestationVerifier - verification logic."""

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig
from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCertificateChainException,
    InvalidNonceException,
    InvalidSecurityLevelException,
    PyAttestException,
    RevokedCertificateException,
)
from pyattest.key_description import (
    SECURITY_LEVEL_SOFTWARE,
    SECURITY_LEVEL_STRONG_BOX,
)
from pyattest.testutils.factories.attestation import google_key as factory

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def nonce():
    return os.urandom(32)


# --- Happy path ---


def test_happy_path(nonce):
    """Valid TEE key attestation."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()

    data = attestation.data["data"]
    assert data["security_level"] == "TrustedEnvironment"
    assert data["challenge"] == nonce
    assert data["package_name"] == "com.example.app"


def test_happy_path_strongbox(nonce):
    """Valid StrongBox key attestation."""
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        security_level=SECURITY_LEVEL_STRONG_BOX,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()
    assert attestation.data["data"]["security_level"] == "StrongBox"


def test_happy_path_production(nonce):
    """Valid TEE attestation in production mode (checks package name)."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Security level ---


def test_invalid_security_level(nonce):
    """Software-backed key should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        security_level=SECURITY_LEVEL_SOFTWARE,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


# --- Nonce ---


def test_invalid_nonce(nonce):
    """Wrong nonce should be rejected."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    wrong_nonce = os.urandom(32)
    attestation = Attestation(attest, wrong_nonce, config)
    with raises(InvalidNonceException):
        attestation.verify()


# --- Certificate chain ---


def test_invalid_certificate_chain(nonce):
    """Attestation without matching root CA should be rejected."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


# --- Package name ---


def test_invalid_package_name(nonce):
    """Wrong package name should be rejected in production mode."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.wrong.package",
        root_ca=root_ca_pem,
        production=True,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_package_name_not_checked_in_dev(nonce):
    """Package name mismatch should pass in non-production mode."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.wrong.package",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Revocation ---


def test_revoked_certificate(nonce):
    """Certificate with a revoked serial should be rejected."""
    import base64
    import json
    from cryptography.x509 import load_der_x509_certificate

    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    chain = json.loads(attest)
    leaf = load_der_x509_certificate(base64.b64decode(chain[0]))

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
        revoked_serials={format(leaf.serial_number, "x")},
    )
    attestation = Attestation(attest, nonce, config)
    with raises(RevokedCertificateException):
        attestation.verify()


def test_revocation_not_checked_when_empty(nonce):
    """Revocation check should pass when revoked_serials is empty."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
        revoked_serials=set(),
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Key origin ---


def test_generated_key_passes(nonce):
    """Key with origin=0 (Generated) should pass."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce, origin=0)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


@pytest.mark.parametrize(
    "origin,label",
    [(1, "Imported"), (2, "Derived"), (3, "Unknown"), (4, "Securely Imported")],
)
def test_non_generated_key_rejected(nonce, origin, label):
    """Keys with origin != 0 (Generated) should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce, origin=origin
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


def test_missing_origin_rejected(nonce):
    """Key with no origin field should be rejected."""
    # Factory always sets origin, so we need to patch the parsed result
    from unittest.mock import patch

    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)

    # Intercept parse_key_description to remove origin from hardware_enforced
    original_parse = __import__(
        "pyattest.key_description", fromlist=["parse_key_description"]
    ).parse_key_description

    def patched_parse(data):
        result = original_parse(data)
        result["hardware_enforced"].pop("origin", None)
        return result

    with patch(
        "pyattest.verifiers.google_key_attestation.parse_key_description", patched_parse
    ):
        with raises(InvalidSecurityLevelException, match="origin"):
            attestation.verify()


# --- APK signature digest ---


def test_signature_digest_match(nonce):
    """Matching signature digest should pass."""
    known_digest = bytes.fromhex("abcdef1234567890" * 4)
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        signature_digest=known_digest,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=[known_digest.hex()],
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


def test_signature_digest_mismatch(nonce):
    """Wrong signature digest should be rejected."""
    known_digest = bytes.fromhex("abcdef1234567890" * 4)
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        signature_digest=known_digest,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=["0000000000000000" * 4],
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_signature_digest_not_checked_when_not_configured(nonce):
    """When apk_signature_digests is None, any digest should pass."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=None,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Adversarial inputs ---


def test_oversized_attestation(nonce):
    """Attestation data over 1MB should be rejected."""
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    huge = "[" + '"AAAA",' * 300000 + '"AAAA"]'  # >1MB of JSON
    attestation = Attestation(huge, nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_empty_attestation(nonce):
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation("[]", nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_invalid_json(nonce):
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation("not json", nonce, config)
    with raises(PyAttestException):
        attestation.verify()


def test_invalid_base64_in_chain(nonce):
    import json

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(json.dumps(["not-valid-base64!!!"]), nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_truncated_der(nonce):
    import base64, json

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    truncated = json.dumps(
        [base64.b64encode(b"\x30\x82\x00\x10" + b"\x00" * 8).decode()]
    )
    attestation = Attestation(truncated, nonce, config)
    with raises((InvalidCertificateChainException, PyAttestException, ValueError)):
        attestation.verify()


def test_bytes_input(nonce):
    """Attestation data passed as bytes should work."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest.encode("utf-8"), nonce, config)
    attestation.verify()


def test_chain_too_long(nonce):
    import json

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(json.dumps(["AAAA"] * 11), nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_json_object_not_array(nonce):
    import json

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(json.dumps({"not": "an array"}), nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_malformed_key_description(nonce):
    """Malformed DER that isn't a valid KeyDescription should raise PyAttestException."""
    import base64
    import json
    import datetime
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate as load_pem
    from cryptography.x509.oid import NameOID

    rk = load_pem_private_key(
        Path("pyattest/testutils/fixtures/root_key.pem").read_bytes(), b"123"
    )
    rc = load_pem(Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes())

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
        .issuer_name(rc.subject)
        .public_key(leaf_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            cx509.UnrecognizedExtension(
                cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                b"\x30\x03\x01\x01\xff",
            ),
            critical=False,
        )
        .sign(rk, hashes.SHA256())
    )

    chain = json.dumps(
        [
            base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
            base64.b64encode(rc.public_bytes(serialization.Encoding.DER)).decode(),
        ]
    )

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(chain, nonce, config)
    with raises(PyAttestException):
        attestation.verify()
