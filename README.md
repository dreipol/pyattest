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
config = AppleConfig(app_id='foo')
attestation = Attestation(key_id, attest, nonce, config)
result = attestation.verify()
```

## Configuration

TBD

## Contribute

`> pipenv run tests`
`> pipenv run coverage`
