import os
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate

from pyattest.assertion import Assertion
from pyattest.configs.apple import AppleConfig
from pyattest.testutils.factories.attestation import apple as apple_factory

root_ca = load_pem_x509_certificate(Path('pyattest/testutils/fixtures/root_cert.pem').read_bytes())
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


@pytest.mark.skip(reason='not yet fully implemented')
def test_happy_path():
    """ Test the basic attest verification where everything works like it should :) """
    attest, public_key = apple_factory.get(app_id='foo', nonce=nonce)
    key_id = sha256(public_key).digest()
    config = AppleConfig(key_id=key_id, app_id='foo', root_ca=root_ca_pem, production=False)

    raw_assertion = b'asdf'
    expected_hash = b'asdf'

    assertion = Assertion(raw_assertion, expected_hash, public_key, config)
    assertion.verify()
