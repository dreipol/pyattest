from typing import Optional

from pyattest.configs.config import Config
from pyattest.verifiers.google import GoogleVerifier


class GoogleConfig(Config):
    verifier_class = GoogleVerifier

    def __init__(self, key_id: bytes, apk_package_name: str, apk_hash: bytes,
                 root_cn: str = 'attest.android.com', root_ca: bytes = None):
        self.key_id = key_id
        self.apk_package_name = apk_package_name
        self.apk_hash = apk_hash
        self.root_cn = root_cn
        self._custom_root_ca = root_ca

    @property
    def root_ca(self) -> Optional[bytes]:
        """ This is only used for simplified unit testing. """
        return self._custom_root_ca
