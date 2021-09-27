from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from pyattest.verifiers.assertion import AssertionVerifier


class GoogleAssertionVerifier(AssertionVerifier):
    def verify(self):
        self.assertion.public_key.verify(self.assertion.raw, self.assertion.expected_hash, ECDSA(hashes.SHA256()))
