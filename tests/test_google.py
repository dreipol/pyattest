from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate

from pyattest.attestation import Attestation
from pyattest.configs.google import GoogleConfig
from tests.factories import attestation as attest_factory
import os

root_cn = 'pyattest-testing-ca.ch'
root_ca = load_pem_x509_certificate(Path('tests/fixtures/root_cert.pem').read_bytes())
nonce = os.urandom(32)


def test_happy_path():
    """ Test the basic attest verification where everything works like it should :) """

    # TODO: We can't validate the cert chain -> try to generate a new root cert with a cn resembling
    # a domainname and then try again. Also we still need to verfiy the apkcertdigest
    attest, public_key = attest_factory.google(apk_package_name='foo', nonce=nonce)
    key_id = sha256(public_key).digest()
    config = GoogleConfig(key_id=key_id, apk_package_name='foo', apk_hash=b'', root_cn=root_cn,
                          root_ca=root_ca.public_bytes(serialization.Encoding.PEM))

    attestation = Attestation(attest, nonce, config)
    result = attestation.verify()

    assert result is True
