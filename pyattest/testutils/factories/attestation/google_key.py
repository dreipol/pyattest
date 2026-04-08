"""
Factory for generating synthetic Android Key Attestation certificate chains for testing.

Builds X.509 certificates with the KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17)
using the pyasn1 schema types defined in pyattest.key_description.

The DER encoding approach for building AuthorizationList fields with explicit tags
follows the pattern used in keiji/android-device-integrity's test suite:
  https://github.com/keiji/android-device-integrity/blob/c9a2b04/server/key_attestation/tests/test_attestation_parser.py
"""

import base64
import datetime
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from pyattest.key_description import (
    AuthorizationList,
    AttestationApplicationIdSchema,
    AttestationPackageInfo,
    KeyDescriptionSequence,
    SecurityLevel,
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    SECURITY_LEVEL_STRONG_BOX,
)
from pyattest.testutils.factories.certificates import key_usage


def _build_attestation_app_id_der(
    package_name: str, signature_digest: bytes = None
) -> bytes:
    """Build DER-encoded AttestationApplicationId with the given package name."""
    pkg_info = AttestationPackageInfo()
    pkg_info.setComponentByName(
        "packageName", univ.OctetString(package_name.encode("utf-8"))
    )
    pkg_info.setComponentByName("version", univ.Integer(1))

    pkg_set = univ.SetOf(componentType=AttestationPackageInfo())
    pkg_set.setComponentByPosition(0, pkg_info)

    sig_set = univ.SetOf(componentType=univ.OctetString())
    sig_set.setComponentByPosition(
        0, univ.OctetString(signature_digest or os.urandom(32))
    )

    app_id = AttestationApplicationIdSchema()
    app_id.setComponentByName("packageInfos", pkg_set)
    app_id.setComponentByName("signatureDigests", sig_set)

    return der_encoder.encode(app_id)


def _build_key_description_der(
    challenge: bytes,
    security_level: int = SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    package_name: str = None,
    origin: int = 0,
    signature_digest: bytes = None,
) -> bytes:
    """Build DER-encoded KeyDescription extension value."""
    key_desc = KeyDescriptionSequence()
    key_desc.setComponentByName("attestationVersion", univ.Integer(300))
    key_desc.setComponentByName(
        "attestationSecurityLevel", SecurityLevel(security_level)
    )
    key_desc.setComponentByName("keyMintVersion", univ.Integer(300))
    key_desc.setComponentByName("keyMintSecurityLevel", SecurityLevel(security_level))
    key_desc.setComponentByName("attestationChallenge", univ.OctetString(challenge))
    key_desc.setComponentByName("uniqueId", univ.OctetString(b""))

    sw_enforced = AuthorizationList()
    if package_name:
        app_id_der = _build_attestation_app_id_der(package_name, signature_digest)
        # Get the schema-defined component type to preserve tags
        comp_type = sw_enforced.getComponentType()["attestationApplicationId"].getType()
        sw_enforced.setComponentByName(
            "attestationApplicationId", comp_type.clone(app_id_der)
        )

    hw_enforced = AuthorizationList()
    # Set noAuthRequired flag
    no_auth_type = hw_enforced.getComponentType()["noAuthRequired"].getType()
    hw_enforced.setComponentByName("noAuthRequired", no_auth_type.clone(value=b""))

    # Set origin
    origin_type = hw_enforced.getComponentType()["origin"].getType()
    hw_enforced.setComponentByName("origin", origin_type.clone(value=origin))

    # Set purpose = SIGN (2)
    purpose_set = hw_enforced.getComponentType()["purpose"].getType().clone()
    purpose_set.setComponentByPosition(0, univ.Integer(2))
    hw_enforced.setComponentByName("purpose", purpose_set)

    key_desc.setComponentByName("softwareEnforced", sw_enforced)
    key_desc.setComponentByName("hardwareEnforced", hw_enforced)

    return der_encoder.encode(key_desc)


def get(
    apk_package_name: str,
    nonce: bytes,
    security_level: int = SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    origin: int = 0,
    signature_digest: bytes = None,
):
    """
    Create a fake Android Key Attestation certificate chain.

    Returns (json_string_of_base64_der_certs, None).
    """
    here = os.path.abspath(os.path.dirname(__file__))
    fixtures = os.path.join(here, "..", "..", "fixtures")

    root_key = load_pem_private_key(
        Path(f"{fixtures}/root_key.pem").read_bytes(), b"123"
    )
    root_cert = load_pem_x509_certificate(
        Path(f"{fixtures}/root_cert.pem").read_bytes()
    )

    # Generate leaf key (EC for key attestation)
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    # Build the KeyDescription extension
    key_desc_der = _build_key_description_der(
        challenge=nonce,
        security_level=security_level,
        package_name=apk_package_name,
        origin=origin,
        signature_digest=signature_digest,
    )

    # Create leaf certificate with the attestation extension
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(key_usage, critical=False)
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                key_desc_der,
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    # Encode as JSON array of base64 DER certs
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    root_der = root_cert.public_bytes(serialization.Encoding.DER)

    cert_chain_json = json.dumps(
        [
            base64.b64encode(leaf_der).decode(),
            base64.b64encode(root_der).decode(),
        ]
    )

    return cert_chain_json, None
