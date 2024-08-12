from abc import ABC, abstractmethod

from pyattest.attestation import Attestation


class AttestationVerifier(ABC):
    def __init__(self, attestation: Attestation):
        self.attestation = attestation

    @abstractmethod
    def verify(self): ...
