class AlgebraError(BaseException):
    """
    Raised in case of algebraic incompatibility
    """
    pass

class WrongCryptoError(BaseException):
    """
    Raised when no cryptosystem exists for the provided parameters
    """
    pass

class WeakCryptoError(BaseException):
    """
    Raised when the requested cryptosystem does not meet
    the required security standards
    """
    pass

class InvalidKeyError(BaseException):
    """
    Raised when the provided private key is not valid in the current context
    """
    pass

class InvalidFactorError(BaseException):
    """
    Raised when a trustee's factors could not be validated
    """
    pass

class BallotDecryptionError(BaseException):
    """
    Raised when decryption of a ballot collection could not be validated
    """
    pass
