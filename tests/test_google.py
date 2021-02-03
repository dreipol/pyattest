from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate

from pyattest.attestation import Attestation
from pyattest.configs.google import GoogleConfig
from tests.factories import attestation as attest_factory
import os

root_cn = 'pyattest-testing-leaf.ch'
root_ca = load_pem_x509_certificate(Path('tests/fixtures/root_cert.pem').read_bytes())
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


@pytest.mark.skip(reason='skip')
def test_happy_path():
    """ Test the basic attest verification where everything works like it should :) """
    # TODO: Generate a cert sha256 and return that as key_id in form the factory.
    #       This needs to be apkCertificateDigestSha256.
    attest, public_key = attest_factory.google(apk_package_name='foo', nonce=nonce)
    key_id = sha256(public_key).digest()
    config = GoogleConfig(key_ids=[key_id], apk_package_name='foo', root_cn=root_cn,
                          root_ca=root_ca_pem)

    attestation = Attestation(attest, nonce, config)
    result = attestation.verify()

    assert result is True
