class PyAttestException(Exception):
    pass


class IllegalConfigurationException(PyAttestException):
    pass


class InvalidJWT(PyAttestException):
    pass


class InvalidBasicIntegrity(PyAttestException):
    pass


class InvalidAppIntegrity(PyAttestException):
    pass


class InvalidDeviceIntegrity(PyAttestException):
    pass


class InvalidCtsProfile(PyAttestException):
    pass


class ExtensionNotFoundException(PyAttestException):
    pass


class InvalidNonceException(PyAttestException):
    pass


class InvalidKeyIdException(PyAttestException):
    pass


class InvalidAppIdException(PyAttestException):
    pass


class InvalidCounterException(PyAttestException):
    pass


class InvalidAaguidException(PyAttestException):
    pass


class InvalidCredentialIdException(PyAttestException):
    pass


class InvalidCertificateChainException(PyAttestException):
    pass
