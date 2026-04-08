import json
import urllib.request
from pathlib import Path
from typing import List

from asn1crypto import pem
from asn1crypto.x509 import Certificate

GOOGLE_ROOT_CERTS_URL = "https://android.googleapis.com/attestation/root"
GOOGLE_REVOCATION_STATUS_URL = "https://android.googleapis.com/attestation/status"
_MAX_FETCH_BYTES = 10_000_000  # 10MB cap for fetch responses


def _load_certificate(cert_bytes: bytes) -> Certificate:
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)

    return Certificate.load(cert_bytes)


def parse_google_root_certs(pem_list: list) -> List[Certificate]:
    """
    Parse a list of PEM certificate strings, merge with bundled roots, and
    deduplicate. Use this with your own HTTP client instead of
    ``fetch_google_key_attestation_roots()``.

    Args:
        pem_list: JSON-decoded list of PEM certificate strings from
            https://android.googleapis.com/attestation/root

    Usage with a custom HTTP client::

        import httpx
        from pyattest.verifiers.utils import parse_google_root_certs

        resp = httpx.get("https://android.googleapis.com/attestation/root")
        roots = parse_google_root_certs(resp.json())
    """
    if not isinstance(pem_list, list):
        raise ValueError("Expected a list of PEM certificate strings")

    fetched = [_load_certificate(p.encode()) for p in pem_list]

    # Load bundled roots
    cert_dir = Path(__file__).parent / "../certificates"
    bundled = [
        _load_certificate(p.read_bytes())
        for p in sorted(cert_dir.glob("google_hardware_attestation_root_*.pem"))
    ]

    # Deduplicate by DER bytes
    seen = set()
    merged = []
    for cert in bundled + fetched:
        der = cert.dump()
        if der not in seen:
            seen.add(der)
            merged.append(cert)

    return merged


def fetch_google_key_attestation_roots(
    url: str = GOOGLE_ROOT_CERTS_URL,
) -> List[Certificate]:
    """
    Fetch current Google hardware attestation root certificates and merge
    with the bundled roots, returning a deduplicated list.

    Convenience wrapper around ``parse_google_root_certs()`` that handles
    the HTTP fetch. Use ``parse_google_root_certs()`` directly if you need
    a custom HTTP client or async fetching.
    """
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        data = resp.read(_MAX_FETCH_BYTES + 1)
        if len(data) > _MAX_FETCH_BYTES:
            raise RuntimeError(f"Response from {url} exceeds {_MAX_FETCH_BYTES} bytes")
        pem_list = json.loads(data)
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to fetch root certificates from {url}: {e}") from e

    return parse_google_root_certs(pem_list)


def parse_google_revocation_list(data: dict) -> set:
    """
    Parse Google's revocation status response into a set of revoked serial
    numbers as hex strings. Use this with your own HTTP client instead of
    ``fetch_google_revocation_list()``.

    Args:
        data: JSON-decoded dict from
            https://android.googleapis.com/attestation/status

    Usage with a custom HTTP client::

        import httpx
        from pyattest.verifiers.utils import parse_google_revocation_list

        resp = httpx.get("https://android.googleapis.com/attestation/status")
        revoked = parse_google_revocation_list(resp.json())
    """
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        raise ValueError("Expected a dict with an 'entries' key")

    # Serial numbers in Google's API are hex strings without 0x prefix.
    # Lookup in the verifier uses format(cert.serial_number, "x").
    return {
        serial
        for serial, info in entries.items()
        if isinstance(info, dict) and info.get("status") == "REVOKED"
    }


def fetch_google_revocation_list(
    url: str = GOOGLE_REVOCATION_STATUS_URL,
) -> set:
    """
    Fetch Google's certificate revocation status list.

    Returns a set of revoked certificate serial numbers as hex strings
    (without 0x prefix), matching Google's API format.

    Convenience wrapper around ``parse_google_revocation_list()`` that handles
    the HTTP fetch. Use ``parse_google_revocation_list()`` directly if you need
    a custom HTTP client or async fetching.

    See: https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
    """
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        raw = resp.read(_MAX_FETCH_BYTES + 1)
        if len(raw) > _MAX_FETCH_BYTES:
            raise RuntimeError(f"Response from {url} exceeds {_MAX_FETCH_BYTES} bytes")
        data = json.loads(raw)
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to fetch revocation list from {url}: {e}") from e

    return parse_google_revocation_list(data)
