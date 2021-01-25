import os
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig
from pyattest.exceptions import InvalidAaguidException, InvalidNonceException, InvalidKeyIdException, \
    InvalidAppIdException, InvalidCounterException, InvalidCredentialIdException
from tests import attestation as attest_factory

root_ca = load_pem_x509_certificate(Path('tests/fixtures/root_cert.pem').read_bytes())
nonce = os.urandom(32)


def test_happy_path():
    """ Test the basic attest verification where everything works like it should :) """
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(public_key).digest(), attest, nonce, config)
    result = attestation.verify()

    assert result is True


def test_aaguid():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM), production=True)

    attestation = Attestation(sha256(public_key).digest(), attest, nonce, config)
    with raises(InvalidAaguidException):
        attestation.verify()


def test_nonce():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(public_key).digest(), attest, os.urandom(32), config)
    with raises(InvalidNonceException):
        attestation.verify()


def test_key_id():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(b'invalid_public_key').digest(), attest, nonce, config)
    with raises(InvalidKeyIdException):
        attestation.verify()


def test_app_id():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0)
    config = AppleConfig(app_id='bar', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(public_key).digest(), attest, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_counter():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=9)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(public_key).digest(), attest, nonce, config)
    with raises(InvalidCounterException):
        attestation.verify()


def test_credential_id():
    attest, public_key = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=0,
                                               wrong_public_key=True)
    config = AppleConfig(app_id='foo', root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(sha256(public_key).digest(), attest, nonce, config)
    with raises(InvalidCredentialIdException):
        attestation.verify()
