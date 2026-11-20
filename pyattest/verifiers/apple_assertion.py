import struct
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCounterException,
    InvalidFormatException,
)
from pyattest.verifiers.assertion import AssertionVerifier
from cbor2 import CBORDecodeError, loads as cbor_decode


class AppleAssertionVerifier(AssertionVerifier):
    def verify(self):
        """
        Verify the assertion object accompanied with the request. Each verified assertion reestablishes the legitimacy
        of the client. You typically require this for requests that access sensitive or premium content.
        """
        unpacked = self.unpack(self.assertion.raw)
        authenticator_data = unpacked["authenticator_data"]
        nonce = sha256(authenticator_data + self.assertion.expected_hash).digest()

        self.assertion.public_key.verify(
            unpacked["raw"]["signature"], nonce, ECDSA(hashes.SHA256())
        )
        self.verify_app_id(unpacked["rp_id"])
        self.verify_counter(unpacked["counter"])

        self.assertion.verified_data(unpacked)

    def verify_app_id(self, rp_id: bytes):
        """
        Compute the SHA-256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator
        data.
        """
        if rp_id != sha256(self.assertion.config.app_id.encode()).digest():
            raise InvalidAppIdException

    def verify_counter(self, counter: int):
        """
        Verify that the authenticator data’s counter value is greater than the value from the previous assertion,
        or greater than 0 on the first assertion. Only checked when the caller passes `previous_counter`.
        """
        previous = self.assertion.previous_counter
        if previous is not None and counter <= previous:
            raise InvalidCounterException

    @staticmethod
    def unpack(raw: bytes) -> dict:
        """
        Extract in `verify` method mentioned relevant data from cbor encoded raw bytes input.

        Raises InvalidFormatException if the input is not an App Attest assertion object.
        """
        try:
            raw = cbor_decode(raw)
        except (CBORDecodeError, TypeError, ValueError) as exception:
            raise InvalidFormatException("Assertion is not valid CBOR") from exception

        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("signature"), bytes)
            or not isinstance(raw.get("authenticatorData"), bytes)
        ):
            raise InvalidFormatException(
                "Assertion has no signature or authenticatorData"
            )

        # rp_id (32), flags (1), counter (4)
        if len(raw["authenticatorData"]) < 37:
            raise InvalidFormatException("authenticatorData is too short")

        return {
            "raw": raw,
            "authenticator_data": raw["authenticatorData"],
            "rp_id": raw["authenticatorData"][:32],
            "counter": struct.unpack("!I", raw["authenticatorData"][33:37])[0],
        }
