from pyattest.attestation import Attestation


class Verifier:
    def __init__(self, attestation: Attestation):
        self.attestation = attestation
