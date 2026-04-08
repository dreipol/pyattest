import base64
import hmac
import json
from typing import List, Optional

from asn1crypto.x509 import Certificate
from cryptography import x509 as cx509
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError

from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCertificateChainException,
    InvalidNonceException,
    InvalidSecurityLevelException,
    PyAttestException,
    RevokedCertificateException,
)
from pyattest.key_description import (
    OID_KEY_ATTESTATION,
    SECURITY_LEVEL_NAMES,
    SECURITY_LEVEL_SOFTWARE,
    parse_key_description,
)
from pyattest.verifiers.attestation import AttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class GoogleKeyAttestationVerifier(AttestationVerifier):
    def verify(self):
        """
        Verify Android Key Attestation.

        The attestation is a JSON array of base64-encoded DER certificates,
        where the first certificate is the leaf (attestation key) and the
        last is closest to the root.

        Verification steps:
        1. Decode and validate the certificate chain against Google root CAs
        2. Parse the KeyDescription extension from the leaf certificate
        3. Verify the key was generated on-device (origin == Generated)
        4. Verify the attestation challenge matches the expected nonce
        5. Verify the security level is TEE or StrongBox (not Software)
        6. Verify the package name (if production mode)
        7. Verify APK signature digests (if production mode and configured)
        8. Check certificate revocation (if revoked_serials configured)
        """
        chain, key_description = self.unpack(self.attestation.raw)
        self.verify_nonce(key_description.get("attestation_challenge"))
        self.verify_security_level(
            key_description.get("attestation_security_level"),
            key_description.get("keymint_security_level"),
        )

        self.verify_origin(key_description)

        if self.attestation.config.production:
            self.verify_package_name(key_description)

        security_level_int = key_description.get("attestation_security_level", 0)
        data = {
            "security_level": SECURITY_LEVEL_NAMES.get(
                security_level_int, str(security_level_int)
            ),
            "attestation_version": key_description.get("attestation_version"),
            "challenge": key_description.get("attestation_challenge"),
            "software_enforced": key_description.get("software_enforced", {}),
            "hardware_enforced": key_description.get("hardware_enforced", {}),
        }

        # Extract package name if available
        app_id = key_description.get("software_enforced", {}).get(
            "attestation_application_id", {}
        )
        if app_id.get("package_name"):
            data["package_name"] = app_id["package_name"]

        self.attestation.verified_data({"data": data, "certs": chain})

    def unpack(self, raw):
        """
        Decode the certificate chain and parse the KeyDescription extension.

        Returns (validated_chain, key_description_dict).
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        if len(raw) > 1_000_000:
            raise InvalidCertificateChainException(
                f"Attestation data too large ({len(raw)} bytes, max 1MB)."
            )

        try:
            cert_chain_b64 = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as e:
            raise PyAttestException("Attestation data is not valid JSON.") from e

        if not isinstance(cert_chain_b64, list) or len(cert_chain_b64) == 0:
            raise InvalidCertificateChainException(
                "Certificate chain is empty or not a list."
            )

        if len(cert_chain_b64) > 10:
            raise InvalidCertificateChainException(
                f"Certificate chain too long ({len(cert_chain_b64)} certs, max 10)."
            )

        try:
            der_certs = [base64.b64decode(c, validate=True) for c in cert_chain_b64]
        except Exception as e:
            raise InvalidCertificateChainException(
                "Certificate chain contains invalid base64."
            ) from e

        validated_chain = self.verify_certificate_chain(der_certs)
        self.check_revocation(der_certs)

        # Parse KeyDescription from the leaf certificate (first in chain)
        try:
            leaf_cert = cx509.load_der_x509_certificate(der_certs[0])
        except Exception as e:
            raise InvalidCertificateChainException(
                "Leaf certificate is not valid DER."
            ) from e

        key_description = self._parse_attestation_extension(leaf_cert)

        return validated_chain, key_description

    def verify_certificate_chain(self, der_certs: List[bytes]):
        """
        Validate the certificate chain against Google hardware attestation root CAs.
        """
        root_cas = self.attestation.config.root_cas
        context = ValidationContext(trust_roots=root_cas)

        cert = _load_certificate(der_certs[0])
        intermediates = [_load_certificate(c) for c in der_certs[1:]]

        validator = CertificateValidator(
            cert, intermediates, validation_context=context
        )

        try:
            return validator.validate_usage({"digital_signature"})
        except (PathBuildingError, PathValidationError) as e:
            raise InvalidCertificateChainException from e

    def check_revocation(self, der_certs: List[bytes]):
        """Check if any certificate in the chain has been revoked.

        Serial numbers are compared as hex strings without 0x prefix,
        matching Google's revocation status API format.
        """
        revoked = self.attestation.config.revoked_serials
        if not revoked:
            return
        for cert_der in der_certs:
            cert = cx509.load_der_x509_certificate(cert_der)
            serial_hex = format(cert.serial_number, "x")
            if serial_hex in revoked:
                raise RevokedCertificateException(
                    f"Certificate with serial {serial_hex} has been revoked."
                )

    def verify_nonce(self, challenge: Optional[bytes]):
        """Verify the attestation challenge matches the expected nonce."""
        if not challenge or not hmac.compare_digest(challenge, self.attestation.nonce):
            raise InvalidNonceException

    def verify_security_level(
        self, attestation_level: Optional[int], keymint_level: Optional[int] = None
    ):
        """Reject software-backed keys.

        Checks both attestation and KeyMint security levels are not Software.
        Matching Google's Kotlin reference default (NOT_SOFTWARE): both must be
        TEE or StrongBox, but they don't need to match each other (e.g. StrongBox
        key attested by TEE is valid).

        See: https://github.com/android/keyattestation/blob/b1bf4375/src/main/kotlin/ConstraintConfig.kt
        """
        if attestation_level is None or attestation_level == SECURITY_LEVEL_SOFTWARE:
            raise InvalidSecurityLevelException(
                "Attestation security level is Software or missing."
            )
        if keymint_level is not None and keymint_level == SECURITY_LEVEL_SOFTWARE:
            raise InvalidSecurityLevelException("KeyMint security level is Software.")

    def verify_origin(self, key_description: dict):
        """Verify the key was generated on-device, not imported.

        An imported key (origin=1) in TEE still shows TrustedEnvironment security
        level, but the key material wasn't generated by the device's hardware RNG -
        the importer may still hold a copy. Google's Kotlin reference implementation
        defaults to STRICT(Origin.GENERATED). Always enforced, matching Google's stance.

        See: https://github.com/android/keyattestation/blob/b1bf4375/src/main/kotlin/Verifier.kt
        """
        hw = key_description.get("hardware_enforced", {})
        origin = hw.get("origin")
        if origin != 0:  # 0 = GENERATED; missing origin is also rejected
            raise InvalidSecurityLevelException(
                f"Key origin is {origin} (expected 0=Generated). "
                "Key may have been imported rather than generated on-device."
            )

    def verify_package_name(self, key_description: dict):
        """
        Verify the package name and optionally signature digests.

        Checks all packages in the attestation (supports Android's sharedUserId
        where multiple packages share the same UID). Also verifies APK signature
        digests if configured.
        """
        app_id = key_description.get("software_enforced", {}).get(
            "attestation_application_id", {}
        )
        expected_name = self.attestation.config.apk_package_name
        packages = app_id.get("packages", [])
        package_names = [
            p.get("package_name") for p in packages if p.get("package_name")
        ]

        # Fall back to single package_name for backwards compatibility
        if not package_names:
            single = app_id.get("package_name")
            if single:
                package_names = [single]

        if not package_names or expected_name not in package_names:
            raise InvalidAppIdException

        # Verify APK signature digests if configured
        expected_digests = self.attestation.config.apk_signature_digests
        if expected_digests is not None:
            actual_digests = app_id.get("signature_digests", [])
            if not actual_digests or set(expected_digests) != set(actual_digests):
                raise InvalidAppIdException

    def _parse_attestation_extension(self, cert: cx509.Certificate) -> dict:
        """Extract and parse the KeyDescription extension from the certificate."""
        try:
            oid = cx509.ObjectIdentifier(OID_KEY_ATTESTATION)
            try:
                ext = cert.extensions.get_extension_for_oid(oid)
            except cx509.ExtensionNotFound as e:
                raise PyAttestException(
                    "Key attestation extension not found in certificate."
                ) from e

            if isinstance(ext.value, cx509.UnrecognizedExtension):
                key_desc_bytes = ext.value.value
            elif isinstance(ext.value, bytes):
                key_desc_bytes = ext.value
            else:
                raise PyAttestException(
                    f"Unexpected attestation extension type: {type(ext.value)}"
                )

            return parse_key_description(key_desc_bytes)
        except PyAttestException:
            raise
        except Exception as e:
            raise PyAttestException(
                f"Failed to parse attestation extension: {e}"
            ) from e
