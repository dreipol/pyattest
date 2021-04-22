import struct
from hashlib import sha256
from typing import Dict

from asn1crypto.x509 import Certificate, Extension
from cbor2 import loads as cbor_decode
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError
from certvalidator.path import ValidationPath
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA

from pyattest.exceptions import ExtensionNotFoundException, InvalidNonceException, InvalidKeyIdException, \
    InvalidAppIdException, InvalidCounterException, InvalidAaguidException, InvalidCredentialIdException, \
    InvalidCertificateChainException
from pyattest.verifiers.verifier import Verifier


class AppleVerifier(Verifier):
    def verify(self):
        """
        Verify the given attestation based on the Apple documentation. The attestation is CBOR encoded and after
        decoding contains all relevant data according to the Webauthn specification.

        Raises a PyAttestException as soon as one of the verification steps fails.

        See also:
        Apple Documentation https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
        Webauthn Specification https://www.w3.org/TR/webauthn/#fig-attStructs

        Relevant Data:
        rp_id              AppId SHA-256 digest
        counter            The number of times the app used the attested key to sign an assertion.
        aaguid             Environment
        credential_data    Variable length, contains the credential_id and credential_public_key. The length is
                           set at byte 17 and 18.
        """
        data = self.unpack(self.attestation.raw)

        chain = self.verify_certificate_chain(data['raw']['attStmt']['x5c'])
        self.verify_nonce(data['authenticator_data'], self.attestation.nonce, chain[-1])
        self.verify_key_id(chain[-1])
        self.verify_app_id(data['rp_id'], self.attestation.config)
        self.verify_counter(data['counter'])
        self.verify_aaguid(data['aaguid'])
        self.verify_credential_id(data['credential_id'], chain[-1])

        self.attestation.verified_data({'data': data, 'certs': chain})

    @staticmethod
    def __unpack_credentials_data(authenticator_data: bytes) -> Dict[str, bytes]:
        aaguid = None
        credential_id = None

        if credential_data := authenticator_data[37:]:
            credential_id_length = struct.unpack('!H', credential_data[16:18])[0]
            credential_id = credential_data[18:18 + credential_id_length]
            aaguid = credential_data[:16]

        return {
            'aaguid': aaguid,
            'credential_id': credential_id,
        }

    @classmethod
    def unpack(cls, raw: bytes, auth_data_key: str = 'authData') -> dict:
        """ Extract in `verify` method mentioned relevant data from cbor encoded raw bytes input. """
        raw = cbor_decode(raw)

        authenticator_data = raw[auth_data_key]
        unpacked = {
            'raw': raw,
            'authenticator_data': authenticator_data,
            'rp_id': authenticator_data[:32],
            'counter': struct.unpack('!I', authenticator_data[33:37])[0]
        }
        unpacked.update(cls.__unpack_credentials_data(authenticator_data))
        return unpacked

    @staticmethod
    def verify_credential_id(credential_id: bytes, cert: Certificate):
        """ Verify that the authenticator data’s credentialId field is the same as the key identifier. """
        if credential_id != cert.public_key.sha256:
            raise InvalidCredentialIdException

    def verify_aaguid(self, aaguid: bytes):
        """
        Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development
        environment, or appattest followed by seven 0x00 bytes if operating in the production environment.

        See also: https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_devicecheck_appattest-environment
        """
        if self.attestation.config.production and aaguid == b'appattest\x00\x00\x00\x00\x00\x00\x00':
            return

        if not self.attestation.config.production and aaguid == b'appattestdevelop':
            return

        raise InvalidAaguidException

    @staticmethod
    def verify_counter(counter: int):
        """ Verify that the authenticator data’s counter field equals 0. """
        if counter != 0:
            raise InvalidCounterException

    @staticmethod
    def verify_app_id(rp_id: bytes, config: 'configs.apple.AppleConfig'):
        """
        Compute the SHA-256 hash of your app’s App ID, and verify that this is the same as the authenticator
        data’s RP ID hash.
        """
        if rp_id != sha256(config.app_id.encode()).digest():
            raise InvalidAppIdException

    def verify_key_id(self, cert: Certificate):
        """
        Create the SHA-256 hash of the public key in credCert, and verify that it matches the key
        identifier from your app.
        """
        expected_key_id = cert.public_key.sha256
        if expected_key_id != self.attestation.config.key_id:
            raise InvalidKeyIdException

    def verify_nonce(self, auth_data: bytes, nonce: bytes, cert: Certificate):
        """
        Create clientDataHash as the SHA-256 hash of the one-time challenge sent to your app before performing the
        attest_apple, and append that hash to the end of the authenticator data (authData from the decoded object).

        Generate a new SHA-256 hash of the composite item to create nonce.

        Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1
        sequence. Decode the sequence and extract the single octet string that it contains. Verify that the string
        equals nonce.

        Interactive ASN.1 decoder: https://lapo.it/asn1js/

        Sequence:
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER
              OCTET STRING (38 byte)
                SEQUENCE (1 elem)
                    OCTET STRING (32 byte)
        """
        client_data_hash = auth_data + sha256(nonce).digest()
        calculated_nonce = sha256(client_data_hash).digest()

        # TODO: It would be even nice if we could register the apple oid like they do it
        # with the pdf extension: https://github.com/wbond/asn1crypto/blob/79fa04ec6534c8aa000bf28e1f5bae7f2929bd1a/asn1crypto/pdf.py
        extension = self._get_extension(self.attestation.config.oid, cert)

        # asn1crypto somehow doesn't understand the sequence bellow the octet string, so we can just remove
        # the first 6 bytes to get the correct `expected_nonce`
        expected_nonce = extension[2].contents[6:]
        if calculated_nonce != expected_nonce:
            raise InvalidNonceException

    def verify_certificate_chain(self, chain: list) -> ValidationPath:
        """
        Verify that the x5c array contains the intermediate and leaf certificates for App Attest, starting from the
        credential certificate stored in the first data buffer in the array (credcert). Verify the validity of the
        certificates using Apple’s App Attest root certificate.

        See also: https://www.apple.com/certificateauthority/private/
        """
        cert = chain.pop(0)
        context = ValidationContext(extra_trust_roots=[self.attestation.config.root_ca])
        validator = CertificateValidator(cert, chain, validation_context=context)

        try:
            return validator.validate_usage({'digital_signature'})
        except (PathBuildingError, PathValidationError) as exception:
            raise InvalidCertificateChainException from exception

    @classmethod
    def verify_assertion(cls, signature_header: bytes, client_data_hash: sha256, public_key: EllipticCurvePublicKey,
                         config: 'configs.apple.AppleConfig'):
        """
         Verify the assertion object accompanied with the request.
         Each verified assertion reestablishes the legitimacy of the client.
         You typically require this for requests that access sensitive or premium content.
        """
        unpacked = cls.unpack(signature_header, "authenticatorData")
        authenticator_data = unpacked["authenticator_data"]
        nonce = sha256(authenticator_data + client_data_hash).digest()

        public_key.verify(unpacked["raw"]["signature"], nonce, ECDSA(hashes.SHA256()))

        cls.verify_app_id(unpacked['rp_id'], config)

    #     TODO: Check counter
    #     TODO: Verify embedded challenge atm it should be tested that the snonce is 000...

    @staticmethod
    def _get_extension(name: str, cert: Certificate) -> Extension:
        """ Helper method to get a specific x509 extension from a given certificate. """
        for extension in cert['tbs_certificate']['extensions']:
            if extension['extn_id'].native == name:
                return extension

        raise ExtensionNotFoundException
