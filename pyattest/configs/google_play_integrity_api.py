import base64

from cryptography.hazmat.primitives.serialization import load_der_public_key

from pyattest.configs.config import Config
from pyattest.verifiers.google_assertion import GoogleAssertionVerifier
from pyattest.verifiers.google_play_integrity_attestation import GooglePlayIntegrityAttestationVerifier


class GooglePlayIntegrityApiConfig(Config):
    attestation_verifier_class = GooglePlayIntegrityAttestationVerifier
    assertion_verifier_class = GoogleAssertionVerifier

    def __init__(self, decryption_key: str, verification_key: str, apk_package_name: str, production: bool = False):
        self.decryption_key = base64.standard_b64decode(decryption_key)
        self.verification_key = load_der_public_key(base64.standard_b64decode(verification_key))
        self.apk_package_name = apk_package_name
        self.production = production
