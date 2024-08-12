from abc import ABC, abstractmethod

from pyattest.assertion import Assertion


class AssertionVerifier(ABC):
    def __init__(self, assertion: Assertion):
        self.assertion = assertion

    @abstractmethod
    def verify(self): ...
