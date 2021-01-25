import os

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig
from tests import attestation as attest_factory


def test_happy_path():
    nonce = os.urandom(32)
    attest = attest_factory.create(app_id='foo', nonce=nonce, aaguid=b'appattestdevelop', counter=1)
    config = AppleConfig(app_id='foo', root_ca='asdf')

    attestation = Attestation(b'', attest, nonce, config)
    result = attestation.verify()
    foo = 'bar'
