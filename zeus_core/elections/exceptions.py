class Abortion(BaseException):
    """
    Raised when any predictable fatal event happends during the election (e.g.,
    invalid trustee detection, duplicate voter names etc.), disallowing the
    election to proceed normally. Controller designed so that raising of this
    exception forces the election to terminate gently at stage ``Aborted``.
    """
    pass

class MalformedVoteError(BaseException):
    """
    Raised before vote-signature verification, whenever the corresponding
    vote-text does not have the awaited format (will lead to
    InvalidSignatureError)
    """

class ElectionMismatchError(BaseException):
    """
    Raised during vote-signature verification, whenever the inscribed election
    info (crypto-params, election key, trustees and candidates) extracted from
    the corresponding vote-text do not coincide with those of the current
    election (will lead to InvalidSignatureError).
    """
    pass

class VoterInconsistency(BaseException):
    """
    """

class AuditPublicationError(BaseException):
    """
    """
    pass

class VoteRejectionError(BaseException):
    """
    """
    pass

class InvalidVoteError(BaseException):
    """
    """
    pass
