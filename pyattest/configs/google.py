from typing import Optional, List

from pyattest.configs.config import Config
from pyattest.verifiers.google import GoogleVerifier


class GoogleConfig(Config):
    verifier_class = GoogleVerifier

    def __init__(self, key_ids: List[bytes], apk_package_name: str, production: bool = False,
                 root_cn: str = 'attest.android.com', root_ca: bytes = None):
        self.key_ids = key_ids
        self.apk_package_name = apk_package_name
        self.production = production
        self.root_cn = root_cn
        self._custom_root_ca = root_ca

    @property
    def root_ca(self) -> Optional[bytes]:
        """ This is only used for simplified unit testing. """
        return self._custom_root_ca
