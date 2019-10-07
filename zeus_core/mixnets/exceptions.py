class MixnetError(Exception):
    """
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
