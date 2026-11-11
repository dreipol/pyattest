from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from pyattest.configs.config import Config
from pyattest.exceptions import PyAttestException


class Assertion:
    def __init__(
        self,
        raw: bytes,
        expected_hash: bytes,
        public_key: EllipticCurvePublicKey,
        config: Config,
        previous_counter: Optional[int] = None,
    ):
        """
        `previous_counter` is the counter of the last assertion accepted for this key (0 right after the
        attestation). When it is given, an Apple assertion must carry a higher counter, which rejects a replayed
        assertion. Store the new counter, `data["counter"]`, once the assertion is verified.
        """
        self.raw = raw
        self.expected_hash = expected_hash
        self.public_key = public_key
        self.config = config
        self.previous_counter = previous_counter

        self.verified = False
        self._verified_data = {}

    def verify(self):
        self.config.assertion_verifier_class(self).verify()

    @property
    def data(self):
        if not self.verified:
            raise PyAttestException(
                "Assertion needs to be verified before accessing it."
            )

        return self._verified_data

    def verified_data(self, data: dict):
        """The verifier from the config can set all relevant data once the verification is complete."""
        self.verified = True
        self._verified_data = data
