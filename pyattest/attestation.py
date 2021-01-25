from pyattest.configs.config import Config


class Attestation:
    def __init__(self, key_id: bytes, data: bytes, nonce: bytes, config: Config):
        self.key_id = key_id
        self.data = data
        self.nonce = nonce
        self.config = config

    def verify(self) -> bool:
        return self.config.verifier_class(self).verify()
