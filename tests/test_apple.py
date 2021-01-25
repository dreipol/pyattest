import base64
from pathlib import Path

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig


def test_apple():
    config = AppleConfig(app_id='5LVDC4HW22.ch.dreipol.dreiAttestTestHost')
    attest = Path('stubs/attestation').read_text()

    server_nonce = '1fc6d08a2ffc842e25e4ca0deac203cd'  # Sent beforehand
    key_id = 'mbrDsK6QyPjKoTiliNSETympZqA643NiWIiK6B7vEOw='  # sha256 uf the public key (in request)
    uid = 'registration;A6215681-970F-4761-B352-0F0735F7E86F'  # in request header

    # dreiAttest specific -> does it make sense use pubkey and uid in nonce?
    nonce = (uid + key_id + server_nonce).encode()

    attestation = Attestation(base64.b64decode(key_id), base64.b64decode(attest), nonce, config)
    attestation.verify()

    assert 1 == 1
