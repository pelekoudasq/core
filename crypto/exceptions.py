
class WrongConfigsError(BaseException):
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

class UnloadedCryptoError(BaseException):
    """
    Raised when the primitives of a cryptosystem are requested
    without having loaded (algebraically constructed and
    cryptographically validated) the cryptosystem
    """
    pass

class EncryptionNotPossible(BaseException):
    """
    Raised when encryption under the provided conditions is not possible
    """
    pass

class InvalidPrivateKeyError(BaseException):
    """
    """
    pass
