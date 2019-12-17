"""
Communicates with the VoteValidator and Signer interface of the running election
"""

from zeus_core.election.pattern import Stage
from zeus_core.election.constants import (V_CAST_VOTE, V_AUDIT_REQUEST,
    V_PUBLIC_AUDIT,)
from zeus_core.election.exceptions import VoteRejectionError
from .mixing import Mixing


class Voting(Stage):

    def __init__(self, controller):
        self.serialized_audit_requests = []
        self.serialized_audit_publications = []
        self.serialized_votes = []
        super().__init__(controller, next_stage_cls=Mixing)

    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()

        audit_requests_append = self.serialized_audit_requests.append
        audit_publications_append = self.serialized_audit_publications.append
        votes_append = self.serialized_votes.append
        cast_vote = election.cast_vote
        collected_votes = election.collect_votes()
        for vote in collected_votes:
            try:
                _vote, type, signature = cast_vote(vote)
            except VoteRejectionError:
                #
                # ~ Simply ignore vote under rejection
                #
                pass
            _vote['signature'] = signature
            if type == V_CAST_VOTE: votes_append(_vote)
            elif type == V_AUDIT_REQUEST: audit_requests_append(_vote)
            elif type == V_PUBLIC_AUDIT: audit_publications_append(_vote)


    def export_updates(self):
        """
        """
        election = self.get_controller()

        updates = {}
        updates['votes'] = self.serialized_votes
        updates['cast_vote_index'] = election.get_cast_vote_index()
        updates['cast_votes'] = election.get_cast_votes()
        updates['audit_requests'] = self.serialized_audit_requests
        updates['audit_publications'] = self.serialized_audit_publications
        updates['excluded_voters'] = election.get_excluded_voters()

        return updates
