import base64
from pathlib import Path

import pytest

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig
from pyattest.configs.google import GoogleConfig


@pytest.mark.skip(reason='only internal')
def test_apple():
    """ Special test specific for the attest_apple package. """
    server_nonce = '1fc6d08a2ffc842e25e4ca0deac203cd'  # sent beforehand
    key_id = 'mbrDsK6QyPjKoTiliNSETympZqA643NiWIiK6B7vEOw='  # sha256 uf the public key which is in the request
    uid = 'registration;A6215681-970F-4761-B352-0F0735F7E86F'  # in request header

    config = AppleConfig(key_id=base64.b64decode(key_id), app_id='5LVDC4HW22.ch.dreipol.dreiAttestTestHost')
    attest = Path('fixtures/attest_apple').read_text().rstrip()

    # dreiAttest specific way of generating the attestation nonce
    nonce = (uid + key_id + server_nonce).encode()

    attestation = Attestation(base64.b64decode(attest), nonce, config)
    attestation.verify()

    assert 1 == 1


def test_google():
    key_id = b'noideayet'
    nonce = str.encode('f81d4fae-7dec-11d0-a765-00a0c91e6bf6')

    config = GoogleConfig(key_id=key_id, apk_package_name='ch.dreipol.rezhycle', apk_hash=b'')
    attest = Path('tests/fixtures/attest_google').read_text().rstrip()

    attestation = Attestation(attest, nonce, config)
    result = attestation.verify()

    assert result is True
