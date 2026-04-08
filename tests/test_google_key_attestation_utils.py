"""Tests for Key Attestation fetch/parse utilities."""

from pathlib import Path

from pytest import raises


# --- Parse functions (no network) ---


def test_parse_root_certs_merges_and_deduplicates():
    """parse_google_root_certs should merge fetched + bundled and deduplicate."""
    from pyattest.verifiers.utils import parse_google_root_certs

    bundled_pem = Path(
        "pyattest/certificates/google_hardware_attestation_root_rsa_2022.pem"
    ).read_text()
    roots = parse_google_root_certs([bundled_pem])
    assert len(roots) == 5


def test_parse_root_certs_adds_new():
    """parse_google_root_certs should add a new cert not in the bundle."""
    import datetime
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from pyattest.verifiers.utils import parse_google_root_certs

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        cx509.CertificateBuilder()
        .subject_name(
            cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "New Root")])
        )
        .issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "New Root")]))
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    new_pem = cert.public_bytes(ser.Encoding.PEM).decode()
    roots = parse_google_root_certs([new_pem])
    assert len(roots) == 6


def test_parse_root_certs_not_list():
    from pyattest.verifiers.utils import parse_google_root_certs

    with raises(ValueError, match="Expected a list"):
        parse_google_root_certs({"not": "a list"})


def test_parse_revocation_list():
    from pyattest.verifiers.utils import parse_google_revocation_list

    data = {
        "entries": {
            "abcdef1234": {"status": "REVOKED"},
            "1234567890": {"status": "REVOKED"},
            "fedcba9876": {"status": "SUSPENDED"},
        }
    }
    revoked = parse_google_revocation_list(data)
    assert revoked == {"abcdef1234", "1234567890"}


def test_parse_revocation_list_missing_entries():
    from pyattest.verifiers.utils import parse_google_revocation_list

    with raises(ValueError, match="Expected a dict"):
        parse_google_revocation_list({"no_entries": {}})


def test_parse_revocation_list_not_dict():
    from pyattest.verifiers.utils import parse_google_revocation_list

    with raises(ValueError, match="Expected a dict"):
        parse_google_revocation_list("not a dict")


# --- Fetch wrappers (mocked network) ---


def test_fetch_roots_delegates_to_parse():
    from unittest.mock import patch, MagicMock
    from pyattest.verifiers.utils import fetch_google_key_attestation_roots
    import json

    bundled_pem = Path(
        "pyattest/certificates/google_hardware_attestation_root_rsa_2022.pem"
    ).read_text()
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps([bundled_pem]).encode()

    with patch(
        "pyattest.verifiers.utils.urllib.request.urlopen", return_value=fake_response
    ):
        roots = fetch_google_key_attestation_roots()
    assert len(roots) == 5


def test_fetch_roots_network_error():
    from unittest.mock import patch
    from pyattest.verifiers.utils import fetch_google_key_attestation_roots
    import urllib.error

    with patch(
        "pyattest.verifiers.utils.urllib.request.urlopen",
        side_effect=urllib.error.URLError("timeout"),
    ):
        with raises(RuntimeError, match="Failed to fetch"):
            fetch_google_key_attestation_roots()


def test_fetch_revocation_delegates_to_parse():
    from unittest.mock import patch, MagicMock
    from pyattest.verifiers.utils import fetch_google_revocation_list
    import json

    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(
        {"entries": {"abc": {"status": "REVOKED"}}}
    ).encode()

    with patch(
        "pyattest.verifiers.utils.urllib.request.urlopen", return_value=fake_response
    ):
        revoked = fetch_google_revocation_list()
    assert revoked == {"abc"}


def test_fetch_revocation_network_error():
    from unittest.mock import patch
    from pyattest.verifiers.utils import fetch_google_revocation_list
    import urllib.error

    with patch(
        "pyattest.verifiers.utils.urllib.request.urlopen",
        side_effect=urllib.error.URLError("timeout"),
    ):
        with raises(RuntimeError, match="Failed to fetch"):
            fetch_google_revocation_list()
