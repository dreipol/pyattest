import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.google import GoogleConfig
from pyattest.exceptions import (
    InvalidKeyIdException,
    InvalidCtsProfile,
    InvalidBasicIntegrity,
    InvalidCertificateChainException,
    InvalidAppIdException,
)
import os

from pyattest.testutils.factories.attestation import google as google_factory

root_cn = "pyattest-testing-leaf.ch"
root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


def test_happy_path():
    """Test the basic attest verification where everything works like it should :)"""
    attest, key_id = google_factory.get(apk_package_name="foo", nonce=nonce)
    config = GoogleConfig(
        key_ids=[base64.b64encode(key_id)],
        apk_package_name="foo",
        root_cn=root_cn,
        root_ca=root_ca_pem,
        production=False,
    )

    attestation = Attestation(attest, nonce, config)
    attestation.verify()


def test_key_id():
    attest, key_id = google_factory.get(apk_package_name="foo", nonce=nonce)
    config = GoogleConfig(
        key_ids=[base64.b64encode(b"100%wrong")],
        apk_package_name="foo",
        root_cn=root_cn,
        root_ca=root_ca_pem,
        production=False,
    )

    attestation = Attestation(attest, nonce, config)

    with raises(InvalidKeyIdException):
        attestation.verify()


def test_cts_profile():
    attest, key_id = google_factory.get(
        apk_package_name="foo", nonce=nonce, cts_profile=False
    )
    config = GoogleConfig(
        key_ids=[base64.b64encode(key_id)],
        apk_package_name="foo",
        root_cn=root_cn,
        root_ca=root_ca_pem,
        production=True,
    )

    attestation = Attestation(attest, nonce, config)

    with raises(InvalidCtsProfile):
        attestation.verify()


def test_basic_integrity():
    attest, key_id = google_factory.get(
        apk_package_name="foo", nonce=nonce, basic_integrity=False
    )
    config = GoogleConfig(
        key_ids=[base64.b64encode(key_id)],
        apk_package_name="foo",
        root_cn=root_cn,
        root_ca=root_ca_pem,
        production=True,
    )

    attestation = Attestation(attest, nonce, config)

    with raises(InvalidBasicIntegrity):
        attestation.verify()


def test_apk_package_name():
    attest, key_id = google_factory.get(apk_package_name="foo", nonce=nonce)
    config = GoogleConfig(
        key_ids=[base64.b64encode(key_id)],
        apk_package_name="bar",
        root_cn=root_cn,
        root_ca=root_ca_pem,
        production=True,
    )

    attestation = Attestation(attest, nonce, config)

    with raises(InvalidAppIdException):
        attestation.verify()


def test_certificate_chain():
    attest, key_id = google_factory.get(apk_package_name="foo", nonce=nonce)
    config = GoogleConfig(
        key_ids=[base64.b64encode(key_id)],
        apk_package_name="bar",
        root_cn=root_cn,
        production=True,
    )

    attestation = Attestation(attest, nonce, config)

    with raises(InvalidCertificateChainException):
        attestation.verify()
