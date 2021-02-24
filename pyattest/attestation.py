from typing import Union

from pyattest.configs.config import Config
from pyattest.exceptions import PyAttestException


class Attestation:
    def __init__(self, raw: Union[bytes, str], nonce: bytes, config: Config):
        self.raw = raw  # The raw attestation the verifier expects
        self.nonce = nonce
        self.config = config

        self.verified = False
        self._verified_data = {}

    @property
    def data(self):
        if not self.verified:
            raise PyAttestException('Attestation needs to be verified before accessing it.')

        return self._verified_data

    def verify(self):
        self.config.verifier_class(self).verify()

    def verified_data(self, data: dict):
        """ The verifier from the config can set all relevant data once the verification is complete. """
        self.verified = True
        self._verified_data = data
