import base64
from pathlib import Path

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig


def test_apple():
    config = AppleConfig('TZV22A8N6Q.ch.pyattest.test')
    data = Path('stubs/attestation').read_text()
    nonce = '1fc6d08a2ffc842e25e4ca0deac203cd'

    attestation = Attestation(base64.b64decode(data), bytes.fromhex(nonce), config)
    attestation.verify()

    assert 1 == 1
