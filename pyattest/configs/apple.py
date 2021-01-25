from pyattest.configs.config import Config
from pyattest.verifiers.apple import AppleVerifier


class AppleConfig(Config):
    verifier_class = AppleVerifier

    def __init__(self, app_id: str, production: bool = False, root_ca: bytes = None):
        self.app_id = app_id
        self.production = production
        self._custom_root_ca = root_ca

    @property
    def oid(self) -> str:
        """ Object Identifier of the certificate extension containing our nonce. """
        return '1.2.840.113635.100.8.2'

    @property
    def root_ca(self) -> bytes:
        """
        Apples App Attestation Root CA. This can be overwritten for easier testing.

        See also: https://www.apple.com/certificateauthority/private/
        """
        if self._custom_root_ca:
            # Dynamically load from tests/fixtures
            return b"""-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUKjXRVMO4RtM2Bq8+qTX/Ea1gjOEwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UECgwTcHlhdHRlc3QtdGVzdGluZy1jYTAeFw0yMTAxMjUxNDMy
MTlaFw00ODA2MTExNDMyMTlaMB4xHDAaBgNVBAoME3B5YXR0ZXN0LXRlc3Rpbmct
Y2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCcR7RZvJiczSVm+np
bn9Ly1OCRi5EnkiwHtMt9QDFV69LU8NJJWHxgTVvnu7EYVcYy88M9pjpUpEuFU7j
L8F++XEYdJ4adZ1gR5kPvhdWHKLi2omf+gxqoRTNWSY4Bh9rbTXrkN+qJ3Urkv12
GJKsH8x0WU408Bkk7aL6vj4PfuWdxk0uhv2EcPAlillXqRYP+i/Qz+5mpyy7DZF0
LxxyYSyZOSRzkdbEz1sfxxYiwgJvCSxu+0oMhN0Rs0wWUSbTs6pDDwmIHwpTRQIS
jUYGf/3iX8E8wzUGdZpRyHVJNqY8Pm9wSihJLnX6sXnaekWilD8w0ZBK1av0uR+O
+4G/AgMBAAGjUzBRMB0GA1UdDgQWBBSL3bGofi5K1n7XkPG1w8CvIZiVXDAfBgNV
HSMEGDAWgBSL3bGofi5K1n7XkPG1w8CvIZiVXDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQCaShthI3PCk30xbSZesxXN6CvyCfnmDV4WEpz5xuKl
unb8a27VoAicKIXNxenzBZvP2NBUNe6YnQ1Gp/zFweyP9xEMFEWrr5o+2NNaCXMd
Z2moGYJLAT82XsWVnIHOmGZWrxsc8YxVxTMca9OYgMq45NV3gojqBHJF+k8JS7w4
aOMblyTgMHdcS2EQJa4ubGkPhvZdcKvINEBQPJuXu0IYOoHvN1Egs+dwM15GgK8j
zTPxgeOYNJ6vlRqVHORNoM/EOmocX3qx3/Skeu2bBTBiVYc/Y/XZlxoe3it/99ha
4kaFsDhouj9LkCeLh+4kfH5wUxkRXjtz2N4LIMEzT6+k
-----END CERTIFICATE-----
            """

        return b"""-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
        """
