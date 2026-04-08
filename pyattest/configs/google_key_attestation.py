"""
Configuration for Android Key Attestation verification.

Root CA certificates are bundled from Google's official sources:
  RSA roots: https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
  ECDSA root: https://github.com/android/keyattestation/blob/b1bf4375/roots.json

There are 4 RSA root re-issuances (same key, different validity periods: 2016, 2019,
2021, 2022) and 1 ECDSA root (2025) for remotely provisioned devices. Older Android
devices chain to older root generations - all 5 are needed for full compatibility.
"""

from pathlib import Path
from typing import List, Optional, Set, Union

from asn1crypto.x509 import Certificate

from pyattest.configs.config import Config
from pyattest.verifiers.google_assertion import GoogleAssertionVerifier
from pyattest.verifiers.google_key_attestation import GoogleKeyAttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class GoogleKeyAttestationConfig(Config):
    attestation_verifier_class = GoogleKeyAttestationVerifier
    assertion_verifier_class = GoogleAssertionVerifier

    def __init__(
        self,
        apk_package_name: str,
        production: bool,
        root_ca: Optional[bytes] = None,
        root_cas: Optional[List[Certificate]] = None,
        revoked_serials: Optional[Set[str]] = None,
        apk_signature_digests: Optional[List[str]] = None,
    ):
        """
        Args:
            apk_package_name: Expected Android package name. Verified against the
                attestation extension in production mode.
            production: If True, enforce package name (and signature digest)
                verification. Set to False for development/testing.
            root_ca: Single root CA as PEM bytes, for testing with a custom root.
            root_cas: Pre-loaded list of root CA certificates. Use
                ``fetch_google_key_attestation_roots()`` to get an up-to-date list.
            revoked_serials: Set of revoked certificate serial numbers as hex strings.
                Use ``fetch_google_revocation_list()`` to get the current list from
                Google. If empty, revocation checking is skipped.
            apk_signature_digests: Expected APK signing certificate SHA-256 digests as
                hex strings. When set in production mode, the verifier checks that the
                attestation's signature digests match exactly. This prevents a different
                app with the same package name (e.g. a repackaged/modified APK) from
                passing verification. Obtain via ``./gradlew signingReport`` in your
                Android project.
        """
        self.apk_package_name = apk_package_name
        self.production = production
        self._custom_root_ca = _load_certificate(root_ca) if root_ca else None
        self._custom_root_cas = root_cas
        self._bundled_root_cas = None
        self.revoked_serials = revoked_serials or set()
        self.apk_signature_digests = apk_signature_digests

    @property
    def root_cas(self) -> List[Certificate]:
        """
        Google hardware attestation root CAs.

        Priority: root_cas (pre-loaded list) > root_ca (single PEM bytes) > bundled certs.
        Bundled certs are loaded once and cached.

        Use ``fetch_google_key_attestation_roots()`` from ``pyattest.verifiers.utils``
        to get an up-to-date list merged with the bundled roots.
        """
        if self._custom_root_cas:
            return self._custom_root_cas

        if self._custom_root_ca:
            return [self._custom_root_ca]

        if self._bundled_root_cas is None:
            cert_dir = Path(__file__).parent / "../certificates"
            self._bundled_root_cas = [
                _load_certificate(p.read_bytes())
                for p in sorted(cert_dir.glob("google_hardware_attestation_root_*.pem"))
            ]
        return self._bundled_root_cas
