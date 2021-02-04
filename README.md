# pyattest

pyattest provides a common interface that helps you verify attestations from
either [Google](https://developer.android.com/training/safetynet/attestation#request-attestation-process)
or [Apple](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server).

## Installation

pyattest is available on PyPI and can be installed via `$ python -m pip install pyattest`

## Usage

### Google

The following parameters are important:

- `key_id`: A base64 encoded sha256 hash of your apps certificate
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

### Apple

The following parameters are important:

- `key_id`: Sha256 hash of the public key form the cert you got back from the attestation
- `app_id`: Your app’s App ID, which is the concatenation of your 10-digit team identifier, a period, and your app’s CFBundleIdentifier value
- `production`: Checks for the appropriate `aaguid`
- `attest`: The apple attestation as binary
- `nonce`: The nonce used to create the attestation

```python
config = AppleConfig(key_id=key_id, app_id='1234ABCDEF.ch.dreipol.dreiDemo', production=True)
attestation = Attestation(attest, nonce, config)

try:
    attestation.verify()
except PyAttestException as exception:
    # Do your thing
    pass
```

