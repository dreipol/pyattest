"""
ASN.1 type definitions and parsing for Android Key Attestation KeyDescription extension.

OID: 1.3.6.1.4.1.11129.2.1.17

Ported from keiji/android-device-integrity (Apache 2.0 license):
  https://github.com/keiji/android-device-integrity/blob/c9a2b04/server/key_attestation/attestation_parser.py

The pyasn1 schema definitions (SecurityLevel, RootOfTrustAsn1, AuthorizationList,
KeyDescriptionSequence, AttestationPackageInfo, AttestationApplicationIdSchema) and
the parsing functions (parse_key_description, parse_authorization_list,
parse_attestation_application_id) are adapted from that file.

Changes from the original:
  - Renamed KeyDescriptionSchemaV4 -> KeyDescriptionSequence
  - Extracted _explicit_tag() helper to reduce repetition
  - Removed attestation_version parameter from parse_authorization_list()
  - Simplified error handling to raise instead of log-and-continue
  - Added debug logging at key parsing points
  - Added attestationIdSecondImei (tag 723) to AuthorizationList
  - parse_attestation_application_id() returns all packages, not just the first
  - Trailing DER bytes after KeyDescription are rejected (not just warned)

The ASN.1 schema follows Google's official KeyDescription specification:
  https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
"""

import logging

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import constraint, namedtype, namedval, tag, univ

logger = logging.getLogger(__name__)

OID_KEY_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17"

# --- Tag constants for AuthorizationList ---

TAG_PURPOSE = 1
TAG_ALGORITHM = 2
TAG_KEY_SIZE = 3
TAG_DIGEST = 5
TAG_PADDING = 6
TAG_EC_CURVE = 10
TAG_RSA_PUBLIC_EXPONENT = 200
TAG_MGF_DIGEST = 203
TAG_ROLLBACK_RESISTANCE = 303
TAG_EARLY_BOOT_ONLY = 305
TAG_ACTIVE_DATETIME = 400
TAG_ORIGINATION_EXPIRE_DATETIME = 401
TAG_USAGE_EXPIRE_DATETIME = 402
TAG_USAGE_COUNT_LIMIT = 405
TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_AUTH_TIMEOUT = 505
TAG_ALLOW_WHILE_ON_BODY = 506
TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
TAG_UNLOCKED_DEVICE_REQUIRED = 509
TAG_CREATION_DATETIME = 701
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709
TAG_ATTESTATION_ID_BRAND = 710
TAG_ATTESTATION_ID_DEVICE = 711
TAG_ATTESTATION_ID_PRODUCT = 712
TAG_ATTESTATION_ID_SERIAL = 713
TAG_ATTESTATION_ID_IMEI = 714
TAG_ATTESTATION_ID_MEID = 715
TAG_ATTESTATION_ID_MANUFACTURER = 716
TAG_ATTESTATION_ID_MODEL = 717
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719
TAG_DEVICE_UNIQUE_ATTESTATION = 720
TAG_ATTESTATION_ID_SECOND_IMEI = 723
TAG_MODULE_HASH = 724

# --- Security level constants ---

SECURITY_LEVEL_SOFTWARE = 0
SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
SECURITY_LEVEL_STRONG_BOX = 2

SECURITY_LEVEL_NAMES = {
    SECURITY_LEVEL_SOFTWARE: "Software",
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT: "TrustedEnvironment",
    SECURITY_LEVEL_STRONG_BOX: "StrongBox",
}


# --- ASN.1 Type Definitions ---


class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("software", 0),
        ("trustedEnvironment", 1),
        ("strongBox", 2),
    )


class VerifiedBootState(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("Verified", 0),
        ("SelfSigned", 1),
        ("Unverified", 2),
        ("Failed", 3),
    )


class RootOfTrustAsn1(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("verifiedBootKey", univ.OctetString()),
        namedtype.NamedType("deviceLocked", univ.Boolean()),
        namedtype.NamedType("verifiedBootState", VerifiedBootState()),
        namedtype.NamedType("verifiedBootHash", univ.OctetString()),
    )


def _explicit_tag(tag_id, constructed=True):
    fmt = tag.tagFormatConstructed if constructed else tag.tagFormatSimple
    return tag.Tag(tag.tagClassContext, fmt, tag_id)


class AuthorizationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "purpose",
            univ.SetOf(componentType=univ.Integer()).subtype(
                explicitTag=_explicit_tag(TAG_PURPOSE)
            ),
        ),
        namedtype.OptionalNamedType(
            "algorithm",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_ALGORITHM)),
        ),
        namedtype.OptionalNamedType(
            "keySize",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_KEY_SIZE)),
        ),
        namedtype.OptionalNamedType(
            "digest",
            univ.SetOf(componentType=univ.Integer()).subtype(
                explicitTag=_explicit_tag(TAG_DIGEST)
            ),
        ),
        namedtype.OptionalNamedType(
            "padding",
            univ.SetOf(componentType=univ.Integer()).subtype(
                explicitTag=_explicit_tag(TAG_PADDING)
            ),
        ),
        namedtype.OptionalNamedType(
            "ecCurve",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_EC_CURVE)),
        ),
        namedtype.OptionalNamedType(
            "rsaPublicExponent",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_RSA_PUBLIC_EXPONENT)),
        ),
        namedtype.OptionalNamedType(
            "mgfDigest",
            univ.SetOf(componentType=univ.Integer()).subtype(
                explicitTag=_explicit_tag(TAG_MGF_DIGEST)
            ),
        ),
        namedtype.OptionalNamedType(
            "rollbackResistance",
            univ.Null().subtype(
                explicitTag=_explicit_tag(TAG_ROLLBACK_RESISTANCE, constructed=False)
            ),
        ),
        namedtype.OptionalNamedType(
            "earlyBootOnly",
            univ.Null().subtype(
                explicitTag=_explicit_tag(TAG_EARLY_BOOT_ONLY, constructed=False)
            ),
        ),
        namedtype.OptionalNamedType(
            "activeDateTime",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_ACTIVE_DATETIME)),
        ),
        namedtype.OptionalNamedType(
            "originationExpireDateTime",
            univ.Integer().subtype(
                explicitTag=_explicit_tag(TAG_ORIGINATION_EXPIRE_DATETIME)
            ),
        ),
        namedtype.OptionalNamedType(
            "usageExpireDateTime",
            univ.Integer().subtype(
                explicitTag=_explicit_tag(TAG_USAGE_EXPIRE_DATETIME)
            ),
        ),
        namedtype.OptionalNamedType(
            "usageCountLimit",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_USAGE_COUNT_LIMIT)),
        ),
        namedtype.OptionalNamedType(
            "noAuthRequired",
            univ.Null().subtype(
                explicitTag=_explicit_tag(TAG_NO_AUTH_REQUIRED, constructed=False)
            ),
        ),
        namedtype.OptionalNamedType(
            "userAuthType",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_USER_AUTH_TYPE)),
        ),
        namedtype.OptionalNamedType(
            "authTimeout",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_AUTH_TIMEOUT)),
        ),
        namedtype.OptionalNamedType(
            "allowWhileOnBody",
            univ.Null().subtype(
                explicitTag=_explicit_tag(TAG_ALLOW_WHILE_ON_BODY, constructed=False)
            ),
        ),
        namedtype.OptionalNamedType(
            "trustedUserPresenceRequired",
            univ.Null().subtype(
                explicitTag=_explicit_tag(
                    TAG_TRUSTED_USER_PRESENCE_REQUIRED, constructed=False
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "trustedConfirmationRequired",
            univ.Null().subtype(
                explicitTag=_explicit_tag(
                    TAG_TRUSTED_CONFIRMATION_REQUIRED, constructed=False
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "unlockedDeviceRequired",
            univ.Null().subtype(
                explicitTag=_explicit_tag(
                    TAG_UNLOCKED_DEVICE_REQUIRED, constructed=False
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "creationDateTime",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_CREATION_DATETIME)),
        ),
        namedtype.OptionalNamedType(
            "origin",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_ORIGIN)),
        ),
        namedtype.OptionalNamedType(
            "rootOfTrust",
            RootOfTrustAsn1().subtype(explicitTag=_explicit_tag(TAG_ROOT_OF_TRUST)),
        ),
        namedtype.OptionalNamedType(
            "osVersion",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_OS_VERSION)),
        ),
        namedtype.OptionalNamedType(
            "osPatchLevel",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_OS_PATCH_LEVEL)),
        ),
        namedtype.OptionalNamedType(
            "attestationApplicationId",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_APPLICATION_ID)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdBrand",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_BRAND)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdDevice",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_DEVICE)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdProduct",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_PRODUCT)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdSerial",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_SERIAL)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdImei",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_IMEI)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdMeid",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_MEID)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdManufacturer",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_MANUFACTURER)
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdModel",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_MODEL)
            ),
        ),
        namedtype.OptionalNamedType(
            "vendorPatchLevel",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_VENDOR_PATCH_LEVEL)),
        ),
        namedtype.OptionalNamedType(
            "bootPatchLevel",
            univ.Integer().subtype(explicitTag=_explicit_tag(TAG_BOOT_PATCH_LEVEL)),
        ),
        namedtype.OptionalNamedType(
            "deviceUniqueAttestation",
            univ.Null().subtype(
                explicitTag=_explicit_tag(
                    TAG_DEVICE_UNIQUE_ATTESTATION, constructed=False
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "attestationIdSecondImei",
            univ.OctetString().subtype(
                explicitTag=_explicit_tag(TAG_ATTESTATION_ID_SECOND_IMEI)
            ),
        ),
        namedtype.OptionalNamedType(
            "moduleHash",
            univ.OctetString().subtype(explicitTag=_explicit_tag(TAG_MODULE_HASH)),
        ),
    )


class KeyDescriptionSequence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestationVersion", univ.Integer()),
        namedtype.NamedType("attestationSecurityLevel", SecurityLevel()),
        namedtype.NamedType("keyMintVersion", univ.Integer()),
        namedtype.NamedType("keyMintSecurityLevel", SecurityLevel()),
        namedtype.NamedType("attestationChallenge", univ.OctetString()),
        namedtype.OptionalNamedType("uniqueId", univ.OctetString()),
        namedtype.NamedType("softwareEnforced", AuthorizationList()),
        namedtype.NamedType("hardwareEnforced", AuthorizationList()),
    )


# --- AttestationApplicationId inner schemas ---


class AttestationPackageInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("packageName", univ.OctetString()),
        namedtype.NamedType("version", univ.Integer()),
    )


class AttestationApplicationIdSchema(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "packageInfos",
            univ.SetOf(componentType=AttestationPackageInfo()),
        ),
        namedtype.NamedType(
            "signatureDigests",
            univ.SetOf(componentType=univ.OctetString()),
        ),
    )


# --- Parsing functions ---


def parse_attestation_application_id(app_id_bytes: bytes) -> dict:
    """Parse the DER-encoded AttestationApplicationId from tag 709."""
    logger.debug("Parsing AttestationApplicationId: %d bytes", len(app_id_bytes))
    try:
        app_id_obj, _ = der_decoder.decode(
            app_id_bytes, asn1Spec=AttestationApplicationIdSchema()
        )
    except PyAsn1Error as e:
        logger.debug("Failed to decode AttestationApplicationId: %s", e)
        raise ValueError("Malformed AttestationApplicationId sequence.") from e

    parsed = {}
    packages = []
    package_infos_set = app_id_obj.getComponentByName("packageInfos")
    if package_infos_set.isValue and len(package_infos_set) > 0:
        for item in package_infos_set:
            if isinstance(item, AttestationPackageInfo):
                pkg = {}
                pkg_name = item.getComponentByName("packageName")
                pkg_version = item.getComponentByName("version")
                if pkg_name is not None and pkg_name.isValue:
                    pkg["package_name"] = bytes(pkg_name).decode("utf-8")
                if pkg_version is not None and pkg_version.isValue:
                    pkg["version"] = int(pkg_version)
                if pkg:
                    packages.append(pkg)
    else:
        logger.debug("AttestationApplicationId has no package infos")

    # Backwards-compatible: keep package_name/version from first entry
    if packages:
        parsed["package_name"] = packages[0].get("package_name")
        parsed["version"] = packages[0].get("version")
    parsed["packages"] = packages

    signatures = []
    sig_digests_set = app_id_obj.getComponentByName("signatureDigests")
    if sig_digests_set.isValue:
        for item in sig_digests_set:
            if isinstance(item, univ.OctetString):
                signatures.append(bytes(item).hex())
    parsed["signature_digests"] = signatures

    logger.debug("Parsed AttestationApplicationId: %s", parsed)
    return parsed


def _parse_root_of_trust(rot_obj: RootOfTrustAsn1) -> dict:
    logger.debug("Parsing RootOfTrust")
    parsed = {}
    try:
        parsed["verified_boot_key"] = bytes(
            rot_obj.getComponentByName("verifiedBootKey")
        ).hex()
        parsed["device_locked"] = bool(rot_obj.getComponentByName("deviceLocked"))
        parsed["verified_boot_state"] = int(
            rot_obj.getComponentByName("verifiedBootState")
        )
        parsed["verified_boot_hash"] = bytes(
            rot_obj.getComponentByName("verifiedBootHash")
        ).hex()
    except (TypeError, ValueError, PyAsn1Error, AttributeError) as e:
        logger.error("Error parsing RootOfTrust: %s", e)
        return {}
    return parsed


def parse_authorization_list(auth_list_obj: AuthorizationList) -> dict:
    """Parse an AuthorizationList ASN.1 object into a dict."""
    logger.debug("Parsing AuthorizationList")
    parsed = {}

    # Integer fields
    for asn1_name, key in [
        ("algorithm", "algorithm"),
        ("keySize", "key_size"),
        ("ecCurve", "ec_curve"),
        ("rsaPublicExponent", "rsa_public_exponent"),
        ("activeDateTime", "active_date_time"),
        ("originationExpireDateTime", "origination_expire_date_time"),
        ("usageExpireDateTime", "usage_expire_date_time"),
        ("usageCountLimit", "usage_count_limit"),
        ("userAuthType", "user_auth_type"),
        ("authTimeout", "auth_timeout"),
        ("creationDateTime", "creation_datetime"),
        ("origin", "origin"),
        ("osVersion", "os_version"),
        ("osPatchLevel", "os_patch_level"),
        ("vendorPatchLevel", "vendor_patch_level"),
        ("bootPatchLevel", "boot_patch_level"),
    ]:
        comp = auth_list_obj.getComponentByName(asn1_name)
        if comp is not None and comp.isValue:
            parsed[key] = int(comp)

    # SetOf Integer fields
    for asn1_name, key in [
        ("purpose", "purposes"),
        ("digest", "digests"),
        ("padding", "padding"),
        ("mgfDigest", "mgf_digest"),
    ]:
        comp = auth_list_obj.getComponentByName(asn1_name)
        if comp is not None and comp.isValue:
            parsed[key] = [int(c) for c in comp]

    # Null (boolean flag) fields
    for asn1_name, key in [
        ("rollbackResistance", "rollback_resistance"),
        ("earlyBootOnly", "early_boot_only"),
        ("noAuthRequired", "no_auth_required"),
        ("allowWhileOnBody", "allow_while_on_body"),
        ("trustedUserPresenceRequired", "trusted_user_presence_required"),
        ("trustedConfirmationRequired", "trusted_confirmation_required"),
        ("unlockedDeviceRequired", "unlocked_device_required"),
        ("deviceUniqueAttestation", "device_unique_attestation"),
    ]:
        comp = auth_list_obj.getComponentByName(asn1_name)
        if comp is not None and comp.isValue:
            parsed[key] = True

    # AttestationApplicationId (OctetString containing DER)
    app_id_comp = auth_list_obj.getComponentByName("attestationApplicationId")
    if app_id_comp is not None and app_id_comp.isValue:
        try:
            parsed["attestation_application_id"] = parse_attestation_application_id(
                bytes(app_id_comp)
            )
        except ValueError as e:
            logger.warning("Failed to parse AttestationApplicationId: %s", e)

    # RootOfTrust
    rot_comp = auth_list_obj.getComponentByName("rootOfTrust")
    if rot_comp is not None and rot_comp.isValue:
        if isinstance(rot_comp, RootOfTrustAsn1):
            parsed["root_of_trust"] = _parse_root_of_trust(rot_comp)

    # OctetString ID fields (decode as UTF-8)
    for asn1_name, key in [
        ("attestationIdBrand", "attestation_id_brand"),
        ("attestationIdDevice", "attestation_id_device"),
        ("attestationIdProduct", "attestation_id_product"),
        ("attestationIdSerial", "attestation_id_serial"),
        ("attestationIdImei", "attestation_id_imei"),
        ("attestationIdMeid", "attestation_id_meid"),
        ("attestationIdManufacturer", "attestation_id_manufacturer"),
        ("attestationIdModel", "attestation_id_model"),
        ("attestationIdSecondImei", "attestation_id_second_imei"),
    ]:
        comp = auth_list_obj.getComponentByName(asn1_name)
        if comp is not None and comp.isValue:
            val_bytes = bytes(comp)
            try:
                parsed[key] = val_bytes.decode("utf-8")
            except UnicodeDecodeError:
                parsed[key] = val_bytes.hex()

    # moduleHash
    module_hash_comp = auth_list_obj.getComponentByName("moduleHash")
    if module_hash_comp is not None and module_hash_comp.isValue:
        parsed["module_hash"] = bytes(module_hash_comp).hex()

    return parsed


def parse_key_description(key_desc_bytes: bytes) -> dict:
    """
    Parse the KeyDescription DER bytes from the attestation extension.

    Returns a dict with:
        attestation_version, attestation_security_level, keymint_version,
        keymint_security_level, attestation_challenge, unique_id,
        software_enforced, hardware_enforced
    """
    logger.debug(
        "Parsing KeyDescription: %d bytes (first 64: %s)",
        len(key_desc_bytes),
        key_desc_bytes[:64].hex(),
    )
    try:
        key_desc_obj, rest = der_decoder.decode(
            key_desc_bytes, asn1Spec=KeyDescriptionSequence()
        )
        if rest:
            raise ValueError(
                f"Trailing data after KeyDescription: {len(rest)} extra bytes"
            )
    except PyAsn1Error as e:
        logger.debug("Failed to decode KeyDescription: %s", e)
        raise ValueError(
            "Malformed KeyDescription sequence (schema validation failed)."
        ) from e

    parsed = {}
    parsed["attestation_version"] = int(
        key_desc_obj.getComponentByName("attestationVersion")
    )

    att_sec = key_desc_obj.getComponentByName("attestationSecurityLevel")
    if att_sec is not None and att_sec.isValue:
        parsed["attestation_security_level"] = int(att_sec)

    keymint_ver = key_desc_obj.getComponentByName("keyMintVersion")
    if keymint_ver is not None and keymint_ver.isValue:
        parsed["keymint_version"] = int(keymint_ver)

    keymint_sec = key_desc_obj.getComponentByName("keyMintSecurityLevel")
    if keymint_sec is not None and keymint_sec.isValue:
        parsed["keymint_security_level"] = int(keymint_sec)

    parsed["attestation_challenge"] = bytes(
        key_desc_obj.getComponentByName("attestationChallenge")
    )

    unique_id_comp = key_desc_obj.getComponentByName("uniqueId")
    if unique_id_comp is not None and unique_id_comp.isValue:
        parsed["unique_id"] = bytes(unique_id_comp)
    else:
        parsed["unique_id"] = None

    sw_enforced = key_desc_obj.getComponentByName("softwareEnforced")
    if sw_enforced is not None and sw_enforced.isValue:
        parsed["software_enforced"] = parse_authorization_list(sw_enforced)
    else:
        parsed["software_enforced"] = {}

    hw_enforced = key_desc_obj.getComponentByName("hardwareEnforced")
    if hw_enforced is not None and hw_enforced.isValue:
        parsed["hardware_enforced"] = parse_authorization_list(hw_enforced)
    else:
        parsed["hardware_enforced"] = {}

    logger.debug(
        "KeyDescription parsed: version=%s, security_level=%s, challenge=%d bytes",
        parsed.get("attestation_version"),
        SECURITY_LEVEL_NAMES.get(
            parsed.get("attestation_security_level", -1), "unknown"
        ),
        len(parsed.get("attestation_challenge", b"")),
    )
    return parsed
