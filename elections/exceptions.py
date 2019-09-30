class Abortion(BaseException):
    """
    Raised when any validation or verification fails during the election,
    so that the latter cannot normally proceed. The present package has
    been designed so that raising of this exception forces the election
    to terminate gently at stage ``Aborted``
    """
    pass
