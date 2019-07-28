class UnknownCryptoError(BaseException):
    """
    Raised when the type of the cryptosystem under construction
    cannot be recognized
    """
    pass

class WrongConfigKeysError(BaseException):
    """
    Raised when the provided config keys do not correspond to the
    provided type of the cryptosystem under construction
    """
    pass

class WrongCryptoError(BaseException):
    """
    Raised when no cryptosystem exists for the provided configs
    """
    pass

class WeakCryptoError(BaseException):
    """
    Raised when the cryptosystem determined by the provided parameters
    does not meet the required security standards
    """
    pass

class AlgebraicIncompatibilityError(BaseException):
    """
    Raised when some subset provided arguments are not algebraically
    compatible with the provided cryptosystem's type
    """
    pass

class UnloadedCryptoError(BaseException):
    """
    Raised when the primitives of a cryptosystem are requested
    without having loaded (algebraically constructed and
    cryptographically validated) the cryptosystem
    """
    pass

class ImpossibleEncryptionError(BaseException):
    """
    Raised when encryption under the provided conditions is impossible
    """
    pass
