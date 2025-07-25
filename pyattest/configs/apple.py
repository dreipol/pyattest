from pathlib import Path

from asn1crypto.x509 import Certificate

from pyattest.configs.config import Config
from pyattest.verifiers.apple_assertion import AppleAssertionVerifier
from pyattest.verifiers.apple_attestation import AppleAttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class AppleConfig(Config):
    attestation_verifier_class = AppleAttestationVerifier
    assertion_verifier_class = AppleAssertionVerifier

    def __init__(
        self, key_id: bytes, app_id: str, production: bool, root_ca: bytes = None
    ):
        self.key_id = key_id
        self.app_id = app_id
        self.production = production
        self._custom_root_ca = root_ca

    @property
    def oid(self) -> str:
        """Object Identifier of the certificate extension containing our nonce."""
        return "1.2.840.113635.100.8.2"

    @property
    def root_ca(self) -> Certificate:
        """
        Apples App Attestation Root CA. This can be overwritten for easier testing.

        See also: https://www.apple.com/certificateauthority/private/
        """
        if self._custom_root_ca:
            bytes =  self._custom_root_ca
        else:
            folder = Path(__file__).parent / "../certificates"
            bytes = Path(folder / "Apple_App_Attestation_Root_CA.pem").read_bytes()

        return _load_certificate(bytes)
