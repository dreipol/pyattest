# pyattest

Todo:
- [ ] Increase coverage (currently 94%) -> Test special cases
- [ ] Add integration with Apple servers
- [ ] Finish readme
- [ ] Publish to pypi

## Installation

TBD

## Usage

```python
config = AppleConfig(key_id=b'sha256_digest_of_public_key', app_id='foo')
attestation = Attestation(attest, nonce, config)
result = attestation.verify()
```

## Configuration

TBD

## Contribute

`> pipenv run tests`
`> pipenv run coverage`
