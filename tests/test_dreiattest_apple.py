import base64
from pathlib import Path

import pytest

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig


@pytest.mark.skip(reason='only internal')
def test_apple():
    """ Special test specific for the dreiattest package. """
    config = AppleConfig(app_id='5LVDC4HW22.ch.dreipol.dreiAttestTestHost')
    attest = Path('fixtures/dreiattest').read_text()

    server_nonce = '1fc6d08a2ffc842e25e4ca0deac203cd'  # sent beforehand
    key_id = 'mbrDsK6QyPjKoTiliNSETympZqA643NiWIiK6B7vEOw='  # sha256 uf the public key which is in the request
    uid = 'registration;A6215681-970F-4761-B352-0F0735F7E86F'  # in request header

    # dreiAttest specific way of generating the attestation nonce
    nonce = (uid + key_id + server_nonce).encode()

    attestation = Attestation(base64.b64decode(key_id), base64.b64decode(attest), nonce, config)
    attestation.verify()

    assert 1 == 1
