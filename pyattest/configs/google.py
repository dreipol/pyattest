from pyattest.configs.config import Config
from pyattest.verifiers.apple import AppleVerifier
from pyattest.verifiers.google import GoogleVerifier


class GoogleConfig(Config):
    verifier_class = GoogleVerifier

    def __init__(self, key_id: bytes, apk_package_name: str, apk_hash: bytes,
                 root_cn: str = 'attest.android.com'):
        self.key_id = key_id
        self.apk_package_name = apk_package_name
        self.apk_hash = apk_hash
        self.root_cn = root_cn
