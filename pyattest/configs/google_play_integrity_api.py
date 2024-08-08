import base64

from cryptography.hazmat.primitives.serialization import load_der_public_key
from typing import Optional, List, Set

from pyattest.configs.config import Config
from pyattest.verifiers.google_assertion import GoogleAssertionVerifier
from pyattest.verifiers.google_play_integrity_attestation import GooglePlayIntegrityAttestationVerifier
from pyattest.exceptions import IllegalConfigurationException


class GooglePlayIntegrityApiConfig(Config):
    attestation_verifier_class = GooglePlayIntegrityAttestationVerifier
    assertion_verifier_class = GoogleAssertionVerifier

    def __init__(self, decryption_key: str, verification_key: str, apk_package_name: str, production: bool,
                 allow_non_play_distribution: bool = False, verify_code_signature_hex: Optional[List[str]] = None,
                 required_device_verdict: str = 'MEETS_DEVICE_INTEGRITY'):
        if allow_non_play_distribution and not verify_code_signature_hex:
            raise IllegalConfigurationException('When allowing distribution through channels other than the Play Store you need to ' +
                                                'provide the sha256 digest of your signing certificate! (Obtain via ./gradlew ' +
                                                'signingReport or set production to false for dev builds)')

        self.decryption_key = base64.standard_b64decode(decryption_key)
        self.verification_key = load_der_public_key(base64.standard_b64decode(verification_key))
        self.apk_package_name = apk_package_name
        self.production = production
        self.allow_non_play_distribution = allow_non_play_distribution
        if verify_code_signature_hex:
            self.verify_code_signature = [self.__convert_signing_digest(hex) for hex in verify_code_signature_hex]
        else:
            self.verify_code_signature = None

        self.required_device_verdict = required_device_verdict

    def __convert_signing_digest(self, hex: str):
        sanitized = hex.replace(':', '')
        digest_bytes = bytearray.fromhex(sanitized)
        base64Signature = base64.urlsafe_b64encode(digest_bytes).decode()
        return base64Signature.replace('=', '')
