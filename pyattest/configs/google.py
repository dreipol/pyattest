from typing import Optional, List

from asn1crypto.x509 import Certificate

from pyattest.configs.config import Config
from pyattest.verifiers.google_assertion import GoogleAssertionVerifier
from pyattest.verifiers.google_attestation import GoogleAttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class GoogleConfig(Config):
    attestation_verifier_class = GoogleAttestationVerifier
    assertion_verifier_class = GoogleAssertionVerifier

    def __init__(
        self,
        key_ids: List[bytes],
        apk_package_name: str,
        production: bool,
        root_cn: str = "attest.android.com",
        root_ca: Optional[bytes] = None,
    ):
        self.key_ids = key_ids
        self.apk_package_name = apk_package_name
        self.production = production
        self.root_cn = root_cn
        self._custom_root_ca = _load_certificate(root_ca) if root_ca else None

    @property
    def root_ca(self) -> Optional[Certificate]:
        """This is only used for simplified unit testing."""
        return self._custom_root_ca
