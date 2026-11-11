import os
from hashlib import sha256
from pathlib import Path

import pytest
from cbor2 import dumps as cbor_encode, loads as cbor_decode
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig
from pyattest.exceptions import (
    InvalidAaguidException,
    InvalidNonceException,
    InvalidKeyIdException,
    InvalidAppIdException,
    InvalidCounterException,
    InvalidCredentialIdException,
    InvalidFormatException,
)
from pyattest.testutils.factories.attestation import apple as apple_factory

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


@pytest.mark.asyncio
async def test_happy_path():
    """Test the basic attest verification where everything works like it should :)"""
    attest, public_key = apple_factory.get(app_id="foo", nonce=nonce)
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, nonce, config)
    await attestation.verify()


@pytest.mark.asyncio
async def test_aaguid():
    attest, public_key = apple_factory.get(app_id="foo", nonce=nonce)
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=True
    )

    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAaguidException):
        await attestation.verify()


@pytest.mark.asyncio
async def test_nonce():
    attest, public_key = apple_factory.get(app_id="foo", nonce=nonce)
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, os.urandom(32), config)
    with raises(InvalidNonceException):
        await attestation.verify()


@pytest.mark.asyncio
async def test_key_id():
    attest, public_key = apple_factory.get(app_id="foo", nonce=nonce)
    key_id = sha256(b"invalid_public_key").digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, nonce, config)
    with raises(InvalidKeyIdException):
        await attestation.verify()


@pytest.mark.asyncio
async def test_app_id():
    attest, public_key = apple_factory.get(app_id="foo", nonce=nonce)
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="bar", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAppIdException):
        await attestation.verify()


@pytest.mark.asyncio
async def test_counter():
    attest, public_key = apple_factory.get(
        app_id="foo", nonce=nonce, aaguid=b"appattestdevelop", counter=9
    )
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, nonce, config)
    with raises(InvalidCounterException):
        await attestation.verify()


@pytest.mark.asyncio
async def test_credential_id():
    attest, public_key = apple_factory.get(
        app_id="foo", nonce=nonce, wrong_public_key=True
    )
    key_id = sha256(public_key).digest()
    config = AppleConfig(
        key_id=key_id, app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(attest, nonce, config)
    with raises(InvalidCredentialIdException):
        await attestation.verify()


def _malformed(change):
    """A valid attestation, decoded, changed by `change` and encoded again."""
    attest, _ = apple_factory.get(app_id="foo", nonce=nonce)
    data = cbor_decode(attest)
    change(data)
    return cbor_encode(data)


MALFORMED_ATTESTATIONS = {
    "empty": lambda: b"",
    "not cbor": lambda: b"\xff\x00",
    "not a map": lambda: cbor_encode([1, 2, 3]),
    "empty map": lambda: cbor_encode({}),
    "wrong fmt": lambda: _malformed(lambda data: data.update(fmt="packed")),
    "no attStmt": lambda: _malformed(lambda data: data.pop("attStmt")),
    "no authData": lambda: _malformed(lambda data: data.pop("authData")),
    "authData not bytes": lambda: _malformed(
        lambda data: data.update(authData="not bytes")
    ),
    "no x5c": lambda: _malformed(lambda data: data["attStmt"].pop("x5c")),
    "empty x5c": lambda: _malformed(lambda data: data["attStmt"].update(x5c=[])),
    "x5c not bytes": lambda: _malformed(
        lambda data: data["attStmt"].update(x5c=["not bytes"])
    ),
    "short authData": lambda: _malformed(
        lambda data: data.update(authData=data["authData"][:54])
    ),
    "truncated credential id": lambda: _malformed(
        lambda data: data.update(authData=data["authData"][:60])
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", MALFORMED_ATTESTATIONS)
async def test_malformed_attestation(case):
    raw = MALFORMED_ATTESTATIONS[case]()
    config = AppleConfig(
        key_id=b"key", app_id="foo", root_ca=root_ca_pem, production=False
    )

    attestation = Attestation(raw, nonce, config)
    with raises(InvalidFormatException):
        await attestation.verify()
