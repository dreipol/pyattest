import base64
from pathlib import Path

import pytest
from asn1crypto import pem, x509

from pyattest.attestation import Attestation
from pyattest.configs.apple import AppleConfig
from pyattest.configs.google import GoogleConfig


@pytest.mark.skip(reason="only internal")
def test_apple():
    """Special test specific for the attest_apple package."""
    server_nonce = "1fc6d08a2ffc842e25e4ca0deac203cd"  # sent beforehand
    key_id = "mbrDsK6QyPjKoTiliNSETympZqA643NiWIiK6B7vEOw="  # SHA-256 uf the public key which is in the request
    uid = "registration;A6215681-970F-4761-B352-0F0735F7E86F"  # in request header

    config = AppleConfig(
        key_id=base64.b64decode(key_id),
        app_id="5LVDC4HW22.ch.dreipol.dreiAttestTestHost",
        production=False,
    )
    attest = Path("tests/fixtures/attest_apple").read_text().rstrip()

    # dreiAttest specific way of generating the attestation nonce
    nonce = (uid + key_id + server_nonce).encode()

    attestation = Attestation(base64.b64decode(attest), nonce, config)
    attestation.verify()


@pytest.mark.skip(reason="only internal")
def test_google():
    nonce = str.encode("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
    cert = """-----BEGIN CERTIFICATE-----
MIIC4jCCAcoCAQEwDQYJKoZIhvcNAQEFBQAwNzEWMBQGA1UEAwwNQW5kcm9pZCBE
ZWJ1ZzEQMA4GA1UECgwHQW5kcm9pZDELMAkGA1UEBhMCVVMwHhcNMTkxMTExMTMw
NzAxWhcNNDkxMTAzMTMwNzAxWjA3MRYwFAYDVQQDDA1BbmRyb2lkIERlYnVnMRAw
DgYDVQQKDAdBbmRyb2lkMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMPuob6rd30zvriza1BUUQEw2k8bEcc5BF/L+H25XdXw3boQ
niM5VFrsThnad//Pf/piOT6Rhd2Vj6DlnY8jCS2aTLOsFu3DPqTI/wcYVIM6iYqw
8X4eW20vbzP8lHYCq+b5PSa1ikaQocsl/4gi4JC9KvCW1M/EJpLPV6SsHoDQLkHf
ahQ7YEL/4pzXzfFW4B+nILB4ez2tjPEv17d2G7LnF14DIqejYVEutjVzT0wjUzCL
w6ZGYeKqcPI9WEsw+e5JXHh37CN4GtuaARcUkzYnqgGCuQqGapV3JHSLh7Zh070W
lNomd6mgFCOylkpwCP1Gs+0MuVBmS0RGOazAhi8CAwEAATANBgkqhkiG9w0BAQUF
AAOCAQEAF2fbDSxygW7ig5VA+a2W7s2PrIpA1Ny6Xh7O0nceTWMnypO5H1bv++M2
/PgSYX5YdCbgXg6rus3WL7PGl40SMwyZde9yTyB8n4DXEzL3faa7SQSPdWpolBFV
SAYHc3ViOTTT1QtHrRj47VKCPGs873/hDM6VSfeonPN6HiS3b70h4c4Mjt8/Aq9g
gmrBM2lV/sP0yrlkA73bEXMMo1HWC/MD8QTc1cREy/3C91iQsIoqY4NJ4ao4bwOf
269SioU5Eko9knyJfDBtX2EDdOfYvy2jbH8Lm7G0v1TJlVXPXnvoQpukRfoclYRF
/ztOeYT8xl4DpIGzVYGarxLnYXK0qA==
-----END CERTIFICATE-----"""
    type_name, headers, der_bytes = pem.unarmor(cert.encode())
    cert = x509.Certificate.load(der_bytes)

    config = GoogleConfig(
        key_ids=[base64.b64encode(cert.sha256)],
        apk_package_name="ch.dreipol.rezhycle",
        production=False,
    )
    attest = Path("tests/fixtures/attest_google").read_text().rstrip()

    attestation = Attestation(attest, nonce, config)
    attestation.verify()
