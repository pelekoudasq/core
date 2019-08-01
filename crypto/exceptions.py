class AlgebraError(BaseException):
    """
    """
    pass

class WrongCryptoError(BaseException):
    """
    Raised when no cryptosystem exists for the provided configs
    """
    pass

class WeakCryptoError(BaseException):
    """
    Raised when the requested cryptosystem does not meet the security standards
    """
    pass

class EncryptionNotPossible(BaseException):
    """
    Raised when encryption of an element is not possible in the current context
    """
    pass

class InvalidKeyError(BaseException):
    """
    Raised when the provided private key is not valid in the current context
    """
    pass
