import base64
from typing import List, Optional, Tuple

import jwt
from asn1crypto import pem
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError
from certvalidator.path import ValidationPath
from jwt import InvalidTokenError

from pyattest.exceptions import PyAttestException, InvalidCertificateChainException, InvalidNonceException, \
    InvalidAppIdException, InvalidBasicIntegrity, InvalidCtsProfile, InvalidKeyIdException
from pyattest.verifiers.verifier import Verifier


class GoogleVerifier(Verifier):
    def verify(self):
        """
        Verify the given attestation based on the Google documentation. The attestation is formatted as JWS object.

        Raises a PyAttestException as soon as one of the verification steps fails.

        See also:
        Google Documentation https://developer.android.com/training/safetynet/attestation
        JWS RFC https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36
        """
        certificate_chain, data = self.unpack(self.attestation.raw)
        self.verify_nonce(data.get('nonce', None))
        self.verify_apk_package_name(data.get('apkPackageName', None))

        # We'll only validate basic integrity and cts profile on production
        if self.attestation.config.production:
            self.verify_basic_integrity(data.get('basicIntegrity', False))
            self.verify_cts_profile(data.get('ctsProfileMatch', False))

        self.verify_key_ids(data.get('apkCertificateDigestSha256', False))

        self.attestation.verified_data({'data': data, 'certs': certificate_chain})

    def unpack(self, jwt_object: str) -> Tuple[ValidationPath, dict]:
        """
        We first need to get the unverified headers to get a hold of the certificate so we can use the certs
        public key to verify the jwt objects signature. The certificate chain needs to be validated first.
        """
        header = jwt.get_unverified_header(jwt_object)
        certificate_chain = self._get_certificates(header)
        public_key = pem.armor('PUBLIC KEY', certificate_chain[-1].public_key.dump())

        try:
            data = jwt.decode(jwt_object, public_key, algorithms=['RS256'])
        except InvalidTokenError as exception:
            raise PyAttestException from exception

        return certificate_chain, data

    def verify_key_ids(self, key_ids: Optional[list]):
        """
        The apkCertificateDigestSha256 can hold multiple certificates and we're comparing them against the list
        of key ids in our config.
        """
        if not key_ids or len(key_ids) != len(self.attestation.config.key_ids):
            raise InvalidKeyIdException

        for key, config_key in zip(key_ids, self.attestation.config.key_ids):
            if key.encode() != config_key:
                raise InvalidKeyIdException

    def verify_cts_profile(self, cts_profile: bool):
        if not cts_profile:
            raise InvalidCtsProfile

    def verify_basic_integrity(self, basic_integrity: bool):
        if not basic_integrity:
            raise InvalidBasicIntegrity

    def verify_apk_package_name(self, package_name: Optional[str]):
        if not package_name or package_name != self.attestation.config.apk_package_name:
            raise InvalidAppIdException

    def verify_nonce(self, nonce: str):
        if base64.b64decode(nonce) != self.attestation.nonce:
            raise InvalidNonceException

    def _get_certificates(self, header: dict) -> ValidationPath:
        """
        Extract the SSL certificate chain from the JWS message. Before returning it, we need verify it otherwise
        it couldn't be used to check the jwt signature.
        """
        chain = list(map(base64.b64decode, header.get('x5c', [])))
        return self.verify_certificate_chain(chain)

    def verify_certificate_chain(self, chain: List[bytes]) -> ValidationPath:
        """
        Validate the SSL certificate chain and use SSL hostname matching to verify that the leaf certificate was
        issued to the hostname attest.android.com.

        We'll also allow to inject custom root ca for unittesting.
        """
        context = None
        if self.attestation.config.root_ca:
            context = ValidationContext(extra_trust_roots=[self.attestation.config.root_ca])

        validator = CertificateValidator(chain[0], chain[1:], validation_context=context)

        try:
            return validator.validate_tls(self.attestation.config.root_cn)
        except (PathBuildingError, PathValidationError) as exception:
            raise InvalidCertificateChainException from exception
