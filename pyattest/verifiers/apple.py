import struct

from certvalidator import CertificateValidator, ValidationContext

from pyattest.attestation import Attestation
from pyattest.verifiers.verifier import Verifier
from cbor2 import loads as cbor_decode


class AppleVerifier(Verifier):
    def __init__(self, attestation: Attestation):
        self.attestation = attestation

    def verify(self):
        """
        rp_id: Hashed AppId
        flag: Flag
        counter: The number of times the app used the attested key to sign an assertion.
        aaguid: Prod vs. Test https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_devicecheck_appattest-environment
        credential_data: Variable length, contains the credential_id and credential_public_key
                         The length is set at byte 17 and 18
        """
        data = cbor_decode(self.attestation.data)

        # Webauthn -> https://www.w3.org/TR/webauthn/#fig-attStructs
        rp_id = data['authData'][:32]  # hashed appId
        counter = struct.unpack('!I', data['authData'][33:37])[0]

        # prod or test?
        credential_data = data['authData'][37:]
        aaguid = credential_data[:16]
        credential_id_length = struct.unpack('!H', credential_data[16:18])[0]
        credential_id = credential_data[18:18 + credential_id_length]
        credential_public_key = credential_id[18 + credential_id_length:]

        self.verify_certificate_chain(data['attStmt']['x5c'])
        foo = 'bar'

    def verify_certificate_chain(self, chain: list):
        """
        raises PathValidationError
        """
        cert = chain.pop(0)
        context = ValidationContext(extra_trust_roots=[self.attestation.config.root_ca])
        validator = CertificateValidator(cert, chain, validation_context=context)
        result = validator.validate_usage({'digital_signature'})
        foo = 'bar'
