class Abortion(BaseException):
    """
    Raised when any predictable fatal event happends during the running election
    (e.g., invalid trustee detection, duplicate voter names etc.), prohibiting
    the election's normal process.

    .. note:: Stage controller has been designed so that raising of this
    exception forces the election to terminate gently at stage ``Aborted``.
    """
    pass

class MalformedVoteError(BaseException):
    """
    Raised before vote-signature verification, whenever the corresponding
    vote-text does not have the awaited format.
    """

class ElectionMismatchError(BaseException):
    """
    Raised during vote-signature verification, whenever the inscribed election
    info extracted from the corresponding vote-text do not coincide with those
    of the running election.
    """
    pass

class InvalidTrusteeError(BaseException):
    """
    Raised when a trustee fails to validate their public key
    """
    pass

class InvalidCandidateError(BaseException):
    """
    Raised when the lists of cancdidates was founs to be invalid
    """
    pass

class InvalidVotersError(BaseException):
    """
    Raised when the lists of voters was founs to be invalid
    """
    pass

class InvalidVoteError(BaseException):
    """
    """
    pass

class VoteRejectionError(BaseException):
    """
    """
    pass

class InvalidVoteSignature(BaseException):
    """
    """
    pass

class InvalidFactorsError(BaseException):
    """
    Raised when a trustee's factors was found to be invalid
    """
    pass
