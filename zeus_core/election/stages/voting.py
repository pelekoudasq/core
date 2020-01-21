"""
Communicates with the VoteValidator and Signer interface of the running election
"""

from copy import deepcopy

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
        adapt_vote = election.adapt_vote
        extract_vote = election.extract_vote
        detect_voter = election.detect_voter
        submit_audit_vote = election.submit_audit_vote
        fix_audit_code = election.fix_audit_code
        submit_audit_request = election.submit_audit_request
        submit_genuine_vote = election.submit_genuine_vote
        for vote in election.collect_votes():
            #
            # TODO: Simplify logical flow?
            #
            _vote = deepcopy(vote)
            try:
                vote = adapt_vote(vote)
            except InvalidVoteError as err:
                # (1) Wrong or extra or missing fields, or
                # (2) Malformed encrypted ballot, or
                # (3) Cryptosystem mismatch, or
                # (4) Election key mismatch
                continue                                        # TODO: Log err?

            (_, _, voter_key, _, fingerprint, voter_audit_code, voter_secret,
                _, _, _, _) = extract_vote(vote)

            try:
                voter, voter_audit_codes = detect_voter(voter_key)
            except VoteRejectionError as err:
                # (1) Voter's key not detected, or
                # (2) Not assigned any audit-codes
                continue                                        # TODO: Log err?

            if voter_secret:
                try:
                    signature = submit_audit_vote(vote, voter_key, fingerprint,
                        voter_audit_code, voter_audit_codes)
                except VoteRejectionError as err:
                    # (1) No audit-code has been provided, or
                    # (2) Provided audit-code not among the assigned ones, or
                    # (3) No audit-request found for the provided fingerprint, or
                    # (4) Vote failed to be verified as audit
                    continue                                    # TODO: Log err?
                _vote['signature'] = signature
                audit_publications_append(_vote)
            else:
                # ~ If no audit-code provided, choose one of the assigned ones (rejects
                # ~ if no audit-code has been provided while skip-audit mode dispabled)
                voter_audit_code = fix_audit_code(voter_audit_code, voter_audit_codes)
                if voter_audit_code not in voter_audit_codes:
                    try:
                        signature = submit_audit_request(fingerprint, voter_key, vote)
                    except VoteRejectionError as err:
                        # Audit-request already submitted
                        # for the provided fingerprint
                        continue                                # TODO: Log err?
                    _vote['signature'] = signature
                    audit_requests_append(_vote)
                else:
                    try:
                        signature = submit_genuine_vote(fingerprint, voter_key, vote)
                    except VoteRejectionError as err:
                        # (1) Vote already cast, or
                        # (2) Vote limit reached, or
                        # (3) Vote failed to be validated
                        continue                                # TODO: Log err?
                    _vote['signature'] = signature
                    votes_append(_vote)


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
