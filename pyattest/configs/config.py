from abc import ABC, abstractmethod


class Config(ABC):
    production = False

    @property
    @abstractmethod
    def verifier_class(self):
        ...
