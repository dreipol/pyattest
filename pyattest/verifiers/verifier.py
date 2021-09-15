from abc import ABC, abstractmethod

from pyattest.attestation import Attestation


class Verifier(ABC):
    def __init__(self, attestation: Attestation):
        self.attestation = attestation

    @abstractmethod
    def verify_attestation(self):
        ...

    @abstractmethod
    def verify_assertion(self):
        ...
