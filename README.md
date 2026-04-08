# pyattest

[![Maintainability](https://api.codeclimate.com/v1/badges/bab7989f664ba4a47501/maintainability)](https://codeclimate.com/repos/603674bad5ad4c0176007ce0/maintainability)

pyattest provides a common interface that helps you verify attestations from either [Google](https://developer.android.com/google/play/integrity) or [Apple](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server). The package works standalone but if you use django and need a full implementation with key generation and storage then [django-dreiattest](https://github.com/dreipol/django-dreiattest) could be of interest for you.

## Installation

pyattest is available on PyPI and can be installed via `$ python -m pip install pyattest`

## Usage

In its most basic form you can create a config instance, create an `Attestation` and verify it. Supported attestation types:

- **Google Play Integrity API** - device and app integrity verification
- **Google SafetyNet** (legacy) - deprecated, use Play Integrity instead
- **Google Key Attestation** - hardware-level proof that a signing key resides in TEE or StrongBox, with package name and challenge verification
- **Apple App Attestation** - hardware-backed app attestation for iOS

### Google Play Integrity API

The following parameters are important:

- `decryption_key`: A Base64 encoded AES key secret as described [here](https://developer.android.com/google/play/integrity/verdict#decrypt-verify)
- `verification_key`: A Base64 encoded public key as described [here](https://developer.android.com/google/play/integrity/verdict#decrypt-verify)
- `apk_package_name`: Name of your apk
- `allow_non_play_distribution`: Set to true if you want to verify apps distributed via other means than Google Play (you need to set `verify_code_signature_hex`) *Note: should not be used for dev builds set `production` to `False` in that case instead.*
- `verify_code_signature_hex`: The sha256 hash of the signing identity you use for distributing your app. This can be obtained using `./gradlew signingReport` in your Android project.
- `required_device_verdict`: If you want to require stronger integrity guarantees pass [the corresponding key](https://developer.android.com/google/play/integrity/setup#optional_device_information) here.
- `attest`: The jwt object string representing the attestation, which is a jws nested in a jwe object
- `nonce`: The nonce used to create the attestation

```python
config = GooglePlayIntegrityApiConfig(
            decryption_key=[decryption_key],
            verification_key=[decryption_key],
            apk_package_name='ch.dreipol.demo',
            production=True,
            allow_non_play_distribution=True,
            verify_code_signature_hex=["00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"],
            required_device_verdict="MEETS_STRONG_INTEGRITY"
        )
attestation = Attestation(attest, nonce, config)

try:
    attestation.verify()
except PyAttestException as exception:
    # Do your thing
    pass
```

### Google (Legacy: SafetyNet)

The following parameters are important:

- `key_id`: A Base64 encoded SHA-256 hash of your apps certificate
- `apk_package_name`: Name of your apk
- `production`: Ignores basic integrity and cts profile check if `False`
- `attest`: The jws object string representing the attestation
- `nonce`: The nonce used to create the attestation

```python
config = GoogleConfig(key_ids=[key_id], apk_package_name='ch.dreipol.demo', production=True)
attestation = Attestation(attest, nonce, config)

try:
    attestation.verify()
except PyAttestException as exception:
    # Do your thing
    pass
```

### Google Key Attestation

Verifies that a signing key is hardware-backed (TEE or StrongBox) via the certificate chain
signed by Google's hardware attestation root CAs. This complements Play Integrity: Play Integrity
proves device/app integrity, Key Attestation proves a specific key is in secure hardware and
can cryptographically verify which package (app) generated the key. The challenge nonce is
always verified; package name verification is optional (production mode only). Key Attestation
is not tied to a specific app distribution channel, so it can be used for apps distributed
outside of Google Play. Unlike Play Integrity, Key Attestation does not provide device integrity
verdicts (e.g. whether the bootloader is unlocked or the device is rooted), app licensing status,
or account details. For full device integrity assurance, combine both.

The following parameters are important:

- `apk_package_name`: Name of your apk package (verified in production mode from the KeyDescription extension)
- `production`: Set to `True` to enforce package name and signature digest verification
- `root_cas`: Optional list of custom root CA certificates (defaults to bundled Google hardware attestation roots)
- `revoked_serials`: Optional set of revoked certificate serial numbers as hex strings (defaults to empty, skipping revocation checks)
- `apk_signature_digests`: Optional list of expected APK signing certificate SHA-256 digests as hex strings. Prevents a repackaged APK with the same package name from passing verification. Obtain via `./gradlew signingReport`.
- `attest`: A JSON array of base64-encoded DER certificates (leaf first, root last)
- `nonce`: Server-generated random bytes for freshness verification (passed to `setAttestationChallenge()` on Android)

```python
import os
from pyattest.attestation import Attestation
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig
from pyattest.exceptions import PyAttestException

# Step 1: Generate a random nonce and send it to the Android client.
# The client passes it to setAttestationChallenge() when generating a key.
nonce = os.urandom(32)
# --> send nonce to client

# Step 2: The client generates an attested key and sends back the certificate chain.
# <-- receive cert_chain_json from client

# Step 3: Verify the attestation.
config = GoogleKeyAttestationConfig(
    apk_package_name='com.example.app',
    production=True,
)
attestation = Attestation(cert_chain_json, nonce, config)

try:
    attestation.verify()
except PyAttestException as exception:
    # Verification failed - invalid chain, wrong challenge, software-backed key, etc.
    pass

# On success, access the verified data:
data = attestation.data["data"]
print(data["security_level"])  # "TrustedEnvironment" or "StrongBox"
print(data["package_name"])    # "com.example.app"
print(data["attestation_version"])  # e.g. 300 or 400
```

The verifier checks:
1. Certificate chain validates against Google's bundled hardware attestation root CAs (or custom roots)
2. Certificates not on Google's revocation list (if `revoked_serials` configured)
3. Key was generated on-device, not imported (always enforced)
4. Attestation challenge matches the expected nonce
5. Both attestation and KeyMint security levels are TEE or StrongBox (not Software)
6. Package name matches (production mode only)
7. APK signature digests match (production mode, if `apk_signature_digests` configured)

To keep root CAs up to date and check for revoked certificates, use the fetch utilities:

```python
from pyattest.verifiers.utils import (
    fetch_google_key_attestation_roots,
    fetch_google_revocation_list,
)

roots = fetch_google_key_attestation_roots()  # merges fetched + bundled, deduplicated
revoked = fetch_google_revocation_list()      # revoked keys

config = GoogleKeyAttestationConfig(
    apk_package_name='com.example.app',
    production=True,
    root_cas=roots,
    revoked_serials=revoked,
)
```

If you use an async HTTP client (aiohttp, httpx) or want to cache responses, use the
parse functions directly:

```python
import httpx
from pyattest.verifiers.utils import parse_google_root_certs, parse_google_revocation_list

roots = parse_google_root_certs(
    httpx.get("https://android.googleapis.com/attestation/root").json()
)
revoked = parse_google_revocation_list(
    httpx.get("https://android.googleapis.com/attestation/status").json()
)
```

#### Hardware-enforced properties and device identity

After verification, you can inspect the hardware-enforced properties to check if the key
requires user authentication (biometric or device PIN/pattern). This is cryptographic proof
from the secure hardware - it cannot be faked by a compromised OS.

```python
hw = attestation.data["data"]["hardware_enforced"]

# user_auth_type is a bitmask set by the app developer at key generation time:
#   1 = password/PIN/pattern only
#   2 = biometric only (fingerprint/face)
#   3 = either (user chooses at time of use)
# If absent, the key has no authentication requirement (noAuthRequired).
auth_type = hw.get("user_auth_type")

if auth_type is None:
    print("Key does not require user authentication")
elif auth_type == 1:
    print("Key requires password/PIN/pattern only")
elif auth_type == 2:
    print("Key requires biometric only")
elif auth_type == 3:
    print("Key accepts biometric or password/PIN (user's choice)")

# auth_timeout: seconds the key remains unlocked after authentication.
# 0 or absent means the key must be authenticated on every use.
timeout = hw.get("auth_timeout")
if timeout:
    print(f"Key stays unlocked for {timeout}s after authentication")
```

You can also read hardware-attested device identity fields. These are embedded by the
device manufacturer at the factory and signed by the TEE - they cannot be faked by a
compromised OS. The Android client must request this with
`setDevicePropertiesAttestationIncluded(true)` at key generation time.

```python
hw = attestation.data["data"]["hardware_enforced"]

for field, label in [
    ("attestation_id_brand", "Brand"),
    ("attestation_id_device", "Device"),
    ("attestation_id_product", "Product"),
    ("attestation_id_model", "Model"),
    ("attestation_id_manufacturer", "Manufacturer"),
    ("attestation_id_serial", "Serial"),
    ("attestation_id_imei", "IMEI"),
    ("attestation_id_second_imei", "Second IMEI"),
]:
    value = hw.get(field)
    if value:
        print(f"{label}: {value}")
# Example output:
#   Brand: google
#   Device: mustang
#   Product: mustang
#   Model: Pixel 10 Pro XL
#   Manufacturer: Google
```

#### Combining Play Integrity and Key Attestation

Play Integrity and Key Attestation serve different purposes and should use separate
nonces/challenges. Play Integrity proves the device and app are genuine; Key Attestation
proves a specific cryptographic key is hardware-backed. Together they provide comprehensive
assurance.

```python
import os
from pyattest.attestation import Attestation
from pyattest.configs.google_play_integrity_api import GooglePlayIntegrityApiConfig
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig

# Step 1: Server generates separate random values and sends them to the client.
# The client uses play_integrity_nonce when calling requestIntegrityToken(), and
# key_attestation_challenge when calling setAttestationChallenge() during key generation.
# The client then sends back the integrity token and the certificate chain.
play_integrity_nonce = os.urandom(32)
key_attestation_nonce = os.urandom(32)
# --> send both to the Android client

# Step 2: Receive responses from the client.
# integrity_token: JWE token string from IntegrityTokenResponse.token()
# cert_chain_json: JSON array of base64-encoded DER certs from KeyStore.getCertificateChain()
# <-- receive integrity_token and cert_chain_json from client

# Step 3: Verify both attestations.

# Verify Play Integrity (device + app integrity)
# integrity_token is the JWE token string returned by the Android Play Integrity API
# (IntegrityTokenResponse.token()), sent by the client to your server.
play_config = GooglePlayIntegrityApiConfig(
    decryption_key=decryption_key,
    verification_key=verification_key,
    apk_package_name='com.example.app',
    production=True,
)
play_attestation = Attestation(integrity_token, play_integrity_nonce, play_config)
play_attestation.verify()

# Verify Key Attestation (hardware-backed key + package name)
# cert_chain_json is a JSON array of base64-encoded DER certificates, sent by the
# Android client after calling KeyStore.getCertificateChain() on the attested key.
# Example: '["MIIC2T...", "MIIB5D...", "MIIFHD..."]'  (leaf -> intermediates -> root)
key_config = GoogleKeyAttestationConfig(
    apk_package_name='com.example.app',
    production=True,
)
key_attestation = Attestation(cert_chain_json, key_attestation_nonce, key_config)
key_attestation.verify()

# Both passed: device is genuine AND the key is in TEE/StrongBox
```

### Apple

The following parameters are important:

- `key_id`: SHA-256 hash of the public key form the cert you got back from the attestation
- `app_id`: Your app’s App ID, which is the concatenation of your 10-digit team identifier, a period, and your app’s CFBundleIdentifier value
- `production`: Checks for the appropriate `aaguid`
- `attest`: The apple attestation as binary
- `nonce`: The nonce used to create the attestation

```python
config = AppleConfig(key_id=key_id, app_id='1234ABCDEF.ch.dreipol.demo', production=True)
attestation = Attestation(attest, nonce, config)

try:
    attestation.verify()
except PyAttestException as exception:
    # Do your thing
    pass
```

### Assertion

Once you verified and obtained a public key, you can use it to `assert` further requests. For a full implementation on how to get to the public key check out [django-dreiattest](https://github.com/dreipol/django-dreiattest/blob/master/dreiattest/key.py). To check if an `assertion` is valid we check if it was signed with given `pem_key`.

- `assertion`: Raw bytes of the assertion you want to test
- `expected_hash`: The hash we want to compare the signature against
- `pem_key`: The public key to verify the signature
- `config`: A `AppleConfig` or `GoogleConfig` instance 

```
assertion = Assertion(assertion, expected_hash, pem_key, config)
assertion.verify()
```





