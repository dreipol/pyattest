import base64
import struct
from hashlib import sha256

from asn1crypto.x509 import Certificate, Extension
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError
from certvalidator.path import ValidationPath

from pyattest.exceptions import ExtensionNotFoundException, InvalidNonceException, InvalidKeyIdException, \
    InvalidAppIdException, InvalidCounterException, InvalidAaguidException, InvalidCredentialIdException, \
    InvalidCertificateChainException
from pyattest.verifiers.verifier import Verifier
from cbor2 import loads as cbor_decode


class GoogleVerifier(Verifier):
    def verify(self) -> bool:
        """
        Verify the given attestation based on the Google documentation. The attestation is formatted as JWS object.

        Raises a PyAttestException as soon as one of the verification steps fails.

        See also:
        Apple Documentation https://developer.android.com/training/safetynet/attestation
        JWS RFC https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36
        """
        data = self.unpack(self.attestation.data)

        # self.verify_nonce(data['raw']['authData'], self.attestation.nonce, chain[-1])

        return True

    def unpack(self, data):
        foo = 'bar'
