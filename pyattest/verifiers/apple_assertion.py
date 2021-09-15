import struct
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from pyattest.verifiers.assertion import AssertionVerifier
from cbor2 import loads as cbor_decode


class AppleAssertionVerifier(AssertionVerifier):
    def verify(self):
        """
        Verify the assertion object accompanied with the request. Each verified assertion reestablishes the legitimacy
        of the client. You typically require this for requests that access sensitive or premium content.
        """
        unpacked = self.unpack(self.assertion.raw)
        authenticator_data = unpacked['authenticator_data']
        nonce = sha256(authenticator_data + self.assertion.expected_hash).digest()

        self.assertion.public_key.verify(unpacked['raw']['signature'], nonce, ECDSA(hashes.SHA256()))

        # cls.verify_app_id(unpacked['rp_id'], config)

    @staticmethod
    def unpack(raw: bytes) -> dict:
        """ Extract in `verify` method mentioned relevant data from cbor encoded raw bytes input. """
        raw = cbor_decode(raw)

        return {
            'raw': raw,
            'authenticator_data': raw['authenticatorData'],
            'rp_id': raw['authenticatorData'][:32],
            'counter': struct.unpack('!I', raw['authenticatorData'][33:37])[0],
        }
