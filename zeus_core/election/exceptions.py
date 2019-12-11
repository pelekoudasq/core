"""
An exception is thought of as

    - *high-level* if it can be raised by at least one method of
                    the elections.ZeusCoreElection abstract base class
    - *low-level* if it can be raised by any method from within
                    `interfaces` and it is not high-level
"""


# --------------------------- High-level exceptions ----------------------------


class Abortion(BaseException):
    """
    Raised when any predictable fatal event happends during the running election
    (e.g., invalid trustee detection, duplicate voter names etc.), prohibiting
    the election's normal process.

    .. note:: The election's underlying state-machine (``StageController``) has
        been designed so that raising of this exception forces the election
        to terminate gently at stage ``Aborted``.
    """
    pass


class InvalidTrusteeError(BaseException):
    """
    Raised when a trustee fails to validate their public key.
    Leads to election abortion.
    """
    pass


class InvalidCandidateError(BaseException):
    """
    Raised when the list of candidates was found to be empty or duplicate
    candidate was detected or candidate with invalid name was detected.
    Leads to election abortion.
    """
    pass


class InvalidVoterError(BaseException):
    """
    Raised when the list of voters was found to be empty or duplicate voter
    name was detected or insufficient slot variation among voters was attained.
    Leads to election abortion.
    """
    pass


class InvalidFactorError(BaseException):
    """
    Raised when some trustee's decryption factor was found to be invalid.
    Leads to election abortion.
    """
    pass


class VoteRejectionError(BaseException):
    """
    Raised when a vote or audit-request or audit-vote was rejected during
    vote submission or casting. Does *not* lead to election abortion.
    """
    pass


# ---------------------------- Low-level exceptions ----------------------------


class MalformedVoteError(BaseException):
    """
    Raised before vote-signature verification, whenever the corresponding
    vote-text does not have the expected format.
    """


class ElectionMismatchError(BaseException):
    """
    Raised during vote-signature verification, whenever the inscribed info
    extracted from the corresponding vote-text does not coincide with
    the running election's params.
    """
    pass


class InvalidVoteError(BaseException):
    """
    """
    pass


class InvalidVoteSignature(BaseException):
    """
    """
    pass
