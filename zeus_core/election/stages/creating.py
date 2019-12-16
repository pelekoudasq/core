"""
"""

from zeus_core.election.pattern import Stage
from zeus_core.crypto.exceptions import InvalidKeyError
from zeus_core.election.exceptions import (InvalidTrusteeError,
        InvalidCandidateError, InvalidVoterError, Abortion)
from .voting import Voting


class Creating(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Voting)

    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()

        try:
            election.create_zeus_keypair()
            election.create_trustees()
            election.create_election_key()
            election.create_candidates()
            election.create_voters_and_audit_codes()
        except (InvalidKeyError, InvalidTrusteeError,
                InvalidCandidateError, InvalidVoterError) as err:
            raise Abortion(err)

        election.broadcast_election()


    def export_updates(self):
        """
        """
        election = self.get_controller()

        updates = dict()
        updates['zeus_public'] = election.get_hex_zeus_public_key()
        updates['zeus_key_proof'] = election.get_hex_zeus_key_proof()
        updates['trustees'] = election.get_trustees_serialized()
        updates['election_key'] = election.get_election_key_serialized()
        updates['candidates'] = election.get_candidates()
        updates['voters'] = election.get_voters()
        updates['audit_codes'] = election.get_audit_codes()

        return updates
