class AlgebraError(BaseException):
    """
    """
    pass

class WrongCryptoError(BaseException):
    """
    Raised when no systemtem exists for the provided configs
    """
    pass

class WeakCryptoError(BaseException):
    """
    Raised when the requested systemtem does not meet the security standards
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
