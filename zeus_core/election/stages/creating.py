"""
"""

from zeus_core.election.pattern import Stage
from zeus_core.crypto.exceptions import InvalidKeyError
from zeus_core.election.exceptions import (InvalidTrusteeError,
        InvalidCandidatesError, InvalidVotersError, Abortion)
from .voting import Voting


class Creating(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Voting)

    def run(self):
        election = self.get_controller()

        try:
            election.create_zeus_keypair()
            election.create_trustees()
            election.create_election_key()
            election.create_candidates()
            election.create_voters_and_audit_codes()
        except (InvalidKeyError, InvalidTrusteeError,
                InvalidCandidatesError, InvalidVotersError) as err:
            raise Abortion(err)