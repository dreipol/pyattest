import base64
import json
from typing import Optional

from jose import jwe, jws

from pyattest.exceptions import (
    PyAttestException,
    InvalidNonceException,
    InvalidAppIdException,
    InvalidAppIntegrity,
    InvalidKeyIdException,
    InvalidDeviceIntegrity,
)
from pyattest.verifiers.attestation import AttestationVerifier


class GooglePlayIntegrityAttestationVerifier(AttestationVerifier):
    def verify(self):
        """
        Verify the given attestation based on the Google documentation. The attestation is a nested JWS in JWE object.

        Raises a PyAttestException as soon as one of the verification steps fails.

        See also:
        Google Documentation https://developer.android.com/google/play/integrity/verdict#decrypt-verify
        """
        payload = self.unpack(self.attestation.raw)
        self.check_request_details(payload.get("requestDetails"))
        if self.attestation.config.production:
            self.check_app_integrity(payload.get("appIntegrity"))
            self.check_device_integrity(payload.get("deviceIntegrity"))

        self.attestation.verified_data({"data": payload})

    def unpack(self, jwt_object: str) -> dict:
        try:
            jwe_token = jwt_object
            jws_token = jwe.decrypt(jwe_token, self.attestation.config.decryption_key)
            payload = jws.verify(
                jws_token, self.attestation.config.verification_key, "ES256"
            )
            return json.loads(payload)
        except Exception as exception:
            raise PyAttestException from exception

    def check_app_integrity(self, app_integrity):
        self.check_verdict(app_integrity.get("appRecognitionVerdict"))
        self.verify_signing_keys(app_integrity.get("certificateSha256Digest"))
        self.verify_apk_package_name(app_integrity.get("packageName"))

    def check_device_integrity(self, device_integrity):
        if self.attestation.config.required_device_verdict not in device_integrity.get(
            "deviceRecognitionVerdict"
        ):
            raise InvalidDeviceIntegrity

    def check_request_details(self, request_details):
        self.verify_nonce(request_details.get("nonce"))
        self.verify_apk_package_name(request_details.get("requestPackageName"))

    def verify_nonce(self, nonce: str):
        if base64.urlsafe_b64decode(nonce) != self.attestation.nonce:
            raise InvalidNonceException

    def check_verdict(self, verdict):
        if verdict == "PLAY_RECOGNIZED":
            pass
        elif (
            self.attestation.config.allow_non_play_distribution
            and verdict == "UNRECOGNIZED_VERSION"
        ):
            pass
        else:
            raise InvalidAppIntegrity

    def verify_signing_keys(self, digest):
        if not self.attestation.config.verify_code_signature:
            return

        if digest != self.attestation.config.verify_code_signature:
            raise InvalidKeyIdException

    def verify_apk_package_name(self, package_name: Optional[str]):
        if not package_name or package_name != self.attestation.config.apk_package_name:
            raise InvalidAppIdException
