"""
"""

class MixnetConstructionError(Exception):
    """
    Raised when invalid or insufficient config is provided at mixnet contruction
    """
    pass

class InvalidMixError(BaseException):
    """
    Raised when a cipher-mix fails to be validated
    """
    pass

class MixNotVerifiedError(BaseException):
    """
    Raised when a cipher-mix fails to be verified
    """
    pass

class RoundNotVerifiedError(BaseException):
    """
    Raised when a mix round fails to be verified
    """
    pass
