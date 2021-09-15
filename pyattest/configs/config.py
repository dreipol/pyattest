from abc import ABC, abstractmethod


class Config(ABC):
    production = False

    @property
    @abstractmethod
    def attestation_verifier_class(self):
        ...

    @property
    @abstractmethod
    def assertion_verifier_class(self):
        ...
