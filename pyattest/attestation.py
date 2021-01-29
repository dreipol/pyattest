from typing import Union

from pyattest.configs.config import Config


class Attestation:
    def __init__(self, data: Union[bytes, str], nonce: bytes, config: Config):
        self.data = data
        self.nonce = nonce
        self.config = config

    def verify(self) -> bool:
        return self.config.verifier_class(self).verify()
