"""
Communicates with the VoteValidator and Signer interface of the running election
"""

from zeus_core.election.pattern import Stage
from zeus_core.election.exceptions import VoteRejectionError
from .mixing import Mixing


class Voting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Mixing)

    def run(self, *data):
        election = self.get_controller()

        cast_vote = election.cast_vote
        for vote in election.collect_votes():
            try:
                cast_vote(vote)
            except VoteRejectionError:
                pass
