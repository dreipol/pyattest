# pyattest

[![Maintainability](https://api.codeclimate.com/v1/badges/bab7989f664ba4a47501/maintainability)](https://codeclimate.com/repos/603674bad5ad4c0176007ce0/maintainability)

pyattest provides a common interface that helps you verify attestations from either [Google](https://developer.android.com/training/safetynet/attestation#request-attestation-process) or [Apple](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server). The package works standalone but if you use django and need a full implementation with key generation and storage then [django-dreiattest](https://github.com/dreipol/django-dreiattest) could be of interest for you.

## Installation

pyattest is available on PyPI and can be installed via `$ python -m pip install pyattest`

## Usage

In it's most basic form you can create either a `GoogleConfig` or `AppleConfig` instance, create an `Attestation` and verify it.

### Google Play Integrity API

TBD

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





