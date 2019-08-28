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
    Raised when the requested cryptosystem does not meet the required security standards
    """
    pass

class InvalidKeyError(BaseException):
    """
    Raised when the provided private key is not valid in the current context
    """
    pass

class InvalidVoteError(BaseException):
    """
    Raised when a submitted vote is found to be invalid
    """
    pass

class InvalidStructureError(BaseException):
    """
    Raised when a submitted signature does not have the expected format
    """
    pass

class InvalidSignatureError(BaseException):
    """
    Raised when a submitted signature cannot be verified under the attached public key
    """
    pass

class InvalidEncryptionError(BaseException):
    """
    Raised when the proof accompanying an encryption cannot be verified
    """
    pass
