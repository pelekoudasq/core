"""
"""
from zeus_core.election.constants import (V_CAST_VOTE, V_AUDIT_REQUEST,
    V_PUBLIC_AUDIT, V_PUBLIC_AUDIT_FAILED,)
from zeus_core.election.exceptions import InvalidVoteError, VoteRejectionError

from .serialization import VoteSerializer
from .validation import VoteValidator
from zeus_core.election.interfaces.signatures import Signer


class VoteSubmitter(VoteSerializer, VoteValidator, Signer):

    def submit_audit_request(self, fingerprint, voter_key, vote):
        """
        Raises VoteRejectionError if an audit-request has already been
        submitted for the inscribed fingerprint.
        Otherwise: modifies the vote's status to audit-request, signs the vote
        and attach to it the signature, stores the audit-request, audit-vote
        and vote, and returns the signature
        """
        # election = self.get_controller()
        #
        if self.get_audit_request(fingerprint):
            err = "Audit-request for vote [%s] already submitted" % (fingerprint,)
            raise VoteRejectionError(err)

        # Modify status
        vote['status'] = V_AUDIT_REQUEST
        vote['previous'] = ''
        vote['index'] = None

        # Sign vote and attach signature
        comments = self.custom_audit_request_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        # Store vote along with audit-request
        self.store_audit_request(fingerprint, voter_key)
        self.store_votes((vote,))

        return V_AUDIT_REQUEST, signature


    def submit_audit_vote(self, vote, voter_key, fingerprint,
            voter_audit_code, voter_audit_codes):
        """
        Raises VoteRejectionError if
            - No audit-code provided
            - Invalid audit-code provided
            - No prior audit-request found for publish-request
        """
        # Check audit-publication prerequisites, reject otherwise
        if not voter_audit_code:
            err = "Invalid audit vote publication: No audit-code provided"
            raise VoteRejectionError(err)
        if voter_audit_code in voter_audit_codes:
            err = "Invalid audit vote publication: Invalid audit-code provided"
            raise VoteRejectionError(err)
        if voter_key != self.get_audit_request(fingerprint):
            err = "No prior audit-request found for publish-request"
            raise VoteRejectionError(err)

        # Audit-vote verification
        vote['status'] = V_PUBLIC_AUDIT
        vote['previous'] = ''
        vote['index'] = None
        missing, failed = self.validate_audit_votes((vote,))
        if missing:
            err = "Missing voter's secret: No randomness provided with audit-vote"
            raise VoteRejectionError(err)
        if failed:
            vote['status'] = V_PUBLIC_AUDIT_FAILED

        # Sign vote and attach signature
        comments = self.custom_audit_publication_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        # Append vote and store inscribed fingerprint as audit-publication
        fingerprint = vote['fingerprint']
        self.store_audit_publication(fingerprint)
        self.store_votes((vote,))

        return V_PUBLIC_AUDIT, signature


    def submit_genuine_vote(self, fingerprint, voter_key, vote):
        """
        """
        if self.get_vote(fingerprint):
            err = "Vote [%s] already cast" % (fingerprint,)
            raise VoteRejectionError(err)
        voter_cast_votes = self.get_voter_cast_votes(voter_key)
        vote_limit = self.get_option('vote_limit')
        if vote_limit and len(voter_cast_votes) >= vote_limit:
            err = "Maximum number of votes reached: %s" % vote_limit
            raise VoteRejectionError(err)

        if not voter_cast_votes:
            previous_fingerprint = ''
        else:
            previous_fingerprint = voter_cast_votes[-1]
        try:
            self.validate_genuine_vote(vote)
        except InvalidVoteError as err:
            raise VoteRejectionError(err)

        vote['status'] = V_CAST_VOTE
        vote['previous'] = previous_fingerprint
        vote['index'] = self.do_index_vote(fingerprint)

        # Sign vote and attach signature
        comments = self.custom_cast_vote_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        self.append_vote(voter_key, fingerprint)
        self.store_votes((vote,))

        ##################################################################
        # DANGER: commit all data to disk before giving a signature out! #
        ##################################################################
        return V_CAST_VOTE, signature


    #  Voter fixation

    def detect_voter(self, voter_key):
        """
        Reject vote if the provided key could not be detected
        Abort election if key was detected but no audit-codes correspond to it
        Return voter and audit-codes otherwise
        """
        # election = self.get_controller()
        #
        voter = self.get_voter(voter_key)
        voter_audit_codes = self.get_voter_audit_codes(voter_key)
        if not voter:
            err = "Invalid voter key"
            raise VoteRejectionError()
        elif not voter_audit_codes:
            err = "Invalid audit-codes inconsistency"
            raise VoteRejectionError(err)

        return voter, voter_audit_codes


    def fix_audit_code(self, voter_audit_code, voter_audit_codes):
        """
        If provided, returns the voter's audit-code
        If not provided and skip-audit mode is enabled, returns the first
        of the provided audit-codes
        If not provided and skip-audit mode is disabled, vote is rejected
        (raises exception)
        """
        # election = self.get_controller()
        #
        if not voter_audit_code:
            skip_audit = self.get_option('skip_audit')
            if skip_audit or skip_audit is None:
                voter_audit_code = voter_audit_codes[0]
            else:
                err = "No `audit_code` provided with the vote while \
                    `skip_audit` disabled"
                raise VoteRejectionError(err)
        return voter_audit_code


    # Message customization

    def custom_audit_publication_message(self, vote):
        """
        """
        return ''

    def custom_audit_request_message(self, vote):
        """
        """
        return ''

    def custom_cast_vote_message(self, vote):
        """
        """
        return ''
