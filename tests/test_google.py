from hashlib import sha256

import pytest

from pyattest.attestation import Attestation
from pyattest.configs.google import GoogleConfig
from tests.factories import attestation as attest_factory
import os

root_cn = 'pyattest-testing-ca'
nonce = os.urandom(32)


@pytest.mark.skip(reason='placeholder')
def test_happy_path():
    """ Test the basic attest verification where everything works like it should :) """
    attest, public_key = attest_factory.google(apk_package_name='foo', nonce=nonce)
    key_id = sha256(public_key).digest()
    config = GoogleConfig(key_id=key_id, apk_package_name='foo', apk_hash=b'', root_cn=root_cn)

    attestation = Attestation(attest, nonce, config)
    result = attestation.verify()

    assert result is True
