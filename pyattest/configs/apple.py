from pathlib import Path

from pyattest.configs.config import Config
from pyattest.verifiers.apple import AppleVerifier


class AppleConfig(Config):
    verifier_class = AppleVerifier

    def __init__(self, key_id: bytes, app_id: str, production: bool = False, root_ca: bytes = None):
        self.key_id = key_id
        self.app_id = app_id
        self.production = production
        self._custom_root_ca = root_ca

    @property
    def oid(self) -> str:
        """ Object Identifier of the certificate extension containing our nonce. """
        return '1.2.840.113635.100.8.2'

    @property
    def root_ca(self) -> bytes:
        """
        Apples App Attestation Root CA. This can be overwritten for easier testing.

        See also: https://www.apple.com/certificateauthority/private/
        """
        if self._custom_root_ca:
            return self._custom_root_ca

        folder = Path(__file__).parent / '../certificates'
        return Path(folder / 'Apple_App_Attestation_Root_CA.pem').read_bytes()
