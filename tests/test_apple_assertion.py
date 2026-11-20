import os

import pytest
from cbor2 import dumps as cbor_encode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from pyattest.assertion import Assertion
from pyattest.configs.apple import AppleConfig
from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCounterException,
    InvalidFormatException,
)
from pyattest.testutils.factories.assertion import apple as apple_factory
from pyattest.verifiers.apple_assertion import AppleAssertionVerifier

client_data_hash = os.urandom(32)


def config(app_id="foo"):
    return AppleConfig(key_id=b"key", app_id=app_id, production=False)


def test_happy_path():
    """Test the basic assertion verification where everything works like it should :)"""
    raw, public_key = apple_factory.get(app_id="foo", client_data_hash=client_data_hash)

    assertion = Assertion(raw, client_data_hash, public_key, config())
    assertion.verify()

    assert assertion.data["counter"] == 1


def test_signature():
    raw, _ = apple_factory.get(app_id="foo", client_data_hash=client_data_hash)
    other_key = ec.generate_private_key(ec.SECP256R1()).public_key()

    assertion = Assertion(raw, client_data_hash, other_key, config())
    with pytest.raises(InvalidSignature):
        assertion.verify()


def test_client_data_hash():
    raw, public_key = apple_factory.get(app_id="foo", client_data_hash=client_data_hash)

    assertion = Assertion(raw, os.urandom(32), public_key, config())
    with pytest.raises(InvalidSignature):
        assertion.verify()


def test_app_id():
    raw, public_key = apple_factory.get(app_id="foo", client_data_hash=client_data_hash)

    assertion = Assertion(raw, client_data_hash, public_key, config(app_id="bar"))
    with pytest.raises(InvalidAppIdException):
        assertion.verify()


def test_counter_increases():
    raw, public_key = apple_factory.get(
        app_id="foo", client_data_hash=client_data_hash, counter=5
    )

    assertion = Assertion(
        raw, client_data_hash, public_key, config(), previous_counter=4
    )
    assertion.verify()

    assert assertion.data["counter"] == 5


@pytest.mark.parametrize("previous_counter", [5, 6])
def test_counter_replayed(previous_counter):
    raw, public_key = apple_factory.get(
        app_id="foo", client_data_hash=client_data_hash, counter=5
    )

    assertion = Assertion(
        raw, client_data_hash, public_key, config(), previous_counter=previous_counter
    )
    with pytest.raises(InvalidCounterException):
        assertion.verify()


def test_counter_not_checked_without_previous_counter():
    raw, public_key = apple_factory.get(
        app_id="foo", client_data_hash=client_data_hash, counter=0
    )

    assertion = Assertion(raw, client_data_hash, public_key, config())
    assertion.verify()


MALFORMED_ASSERTIONS = {
    "empty": b"",
    "not cbor": b"\xff\x00",
    "not a map": cbor_encode("not a map"),
    "empty map": cbor_encode({}),
    "no authenticatorData": cbor_encode({"signature": b"sig"}),
    "no signature": cbor_encode({"authenticatorData": b"\x00" * 37}),
    "signature not bytes": cbor_encode(
        {"signature": "sig", "authenticatorData": b"\x00" * 37}
    ),
    "short authenticatorData": cbor_encode(
        {"signature": b"sig", "authenticatorData": b"\x00" * 36}
    ),
}


@pytest.mark.parametrize("case", MALFORMED_ASSERTIONS)
def test_malformed_assertion(case):
    with pytest.raises(InvalidFormatException):
        AppleAssertionVerifier.unpack(MALFORMED_ASSERTIONS[case])
