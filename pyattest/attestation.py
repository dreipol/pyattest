from pyattest.configs.config import Config


class Attestation:
    def __init__(self, data, nonce: bytes, config: Config):
        self.data = data
        self.nonce = nonce
        self.config = config

    def verify(self):
        return self.config.verifier_class(self).verify()
