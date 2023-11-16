import base64
import os

from _pytest.python_api import raises
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pyattest.attestation import Attestation
from pyattest.configs.google_play_integrity_api import GooglePlayIntegrityApiConfig
from pyattest.exceptions import PyAttestException, InvalidNonceException, InvalidAppIdException, InvalidAppIntegrity, \
    InvalidDeviceIntegrity
from pyattest.testutils.factories.attestation.google import get_play_integrity_api_attestation

nonce = os.urandom(32)


def test_happy_path():
    apk_package_name = 'foo'
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(apk_package_name, nonce,
                                                                                'PLAY_RECOGNIZED',
                                                                                ['MEETS_DEVICE_INTEGRITY'])
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)

    attestation = Attestation(attestation, nonce, config)
    attestation.verify()


def test_invalid_signed_attest_token():
    apk_package_name = 'foo'
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(apk_package_name, nonce,
                                                                                'PLAY_RECOGNIZED',
                                                                                ['MEETS_DEVICE_INTEGRITY'])
    wrong_aes_key = os.urandom(32)
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(wrong_aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)

    attestation = Attestation(attestation, nonce, config)
    with raises(PyAttestException):
        attestation.verify()


def test_invalid_nonce():
    apk_package_name = 'foo'
    invalid_nonce = os.urandom(32)
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(apk_package_name, invalid_nonce,
                                                                                'PLAY_RECOGNIZED',
                                                                                ['MEETS_DEVICE_INTEGRITY'])
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)
    attestation = Attestation(attestation, nonce, config)
    with raises(InvalidNonceException):
        attestation.verify()


def test_invalid_apk_package():
    apk_package_name = 'foo'
    wrong_apk_package_name = 'foo_'
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(wrong_apk_package_name, nonce,
                                                                                'PLAY_RECOGNIZED',
                                                                                ['MEETS_DEVICE_INTEGRITY'])
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)
    attestation = Attestation(attestation, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_invalid_app_integrity():
    apk_package_name = 'foo'
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(apk_package_name, nonce,
                                                                                'PLAY_UNRECOGNIZED',
                                                                                ['MEETS_DEVICE_INTEGRITY'])
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)
    attestation = Attestation(attestation, nonce, config)
    with raises(InvalidAppIntegrity):
        attestation.verify()


def test_invalid_device_integrity():
    apk_package_name = 'foo'
    attestation, verification_key, aes_key = get_play_integrity_api_attestation(apk_package_name, nonce,
                                                                                'PLAY_RECOGNIZED',
                                                                                [])
    config = GooglePlayIntegrityApiConfig(decryption_key=base64.standard_b64encode(aes_key).decode(),
                                          verification_key=base64.standard_b64encode(
                                              verification_key.public_bytes(encoding=Encoding.DER,
                                                                            format=PublicFormat.SubjectPublicKeyInfo))
                                          .decode(),
                                          apk_package_name=apk_package_name, production=True)
    attestation = Attestation(attestation, nonce, config)
    with raises(InvalidDeviceIntegrity):
        attestation.verify()
