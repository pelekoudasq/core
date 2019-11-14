"""
Communicates with the VoteValidator and Signer interface of the running election
"""

from zeus_core.elections.abstracts import Stage
from zeus_core.elections.constants import (V_CAST_VOTE, V_AUDIT_REQUEST,
    V_PUBLIC_AUDIT, V_PUBLIC_AUDIT_FAILED,)
from zeus_core.elections.exceptions import (Abortion, InvalidVoteError,
    VoteRejectionError)
from zeus_core.elections.utils import extract_vote

from .mixing import Mixing


class Voting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Mixing)

    def _generate(self, *data):
        election = self.get_controller()
        cast_vote = self.cast_vote
        for vote in election.collect_votes():
            cast_vote(vote)


    def cast_vote(self, vote):
        """
        General vote handler

        Handles the submitted vote accordingly (audit-request or audit-vote
        or genuine vote) under account of inscribed parameters. Stores the
        submitted vote if all intermediate checks passed

        Rejects vote in case of:
            - wrong or extra fields
            - missing fields
            - malformed encrypted ballot
            - cryptosystem mismatch
            - election key mismatch
            - non-detected voter key
            - no audit-code provided while skip-audit mode disabled
            - (audit-request) audit-request already submitted for the provided fingerprint
            - (audit-vote) no audit-code provided
            - (audit-vote) provided audit-code not among the assigned ones
            - (audit-vote) no audit-request found for the provided fingerprint
            - (audit-vote) failure of audit-vote verification
            - (genuine vote) vote already cast
            - (genuine vote) vote limit reached
            - (genuine vote) failure of vote validation
        """
        election = self.get_controller()

        try:
            vote = election.adapt_vote(vote)
        except InvalidVoteError as err:
            # Wrong or extra or missing fields, or malformed encrypted ballot,
            # or cryptosystem mismatch, or election key mismatch
            raise VoteRejectionError(err)

        (_, _, voter_key, _, fingerprint, voter_audit_code, voter_secret,
            _, _, _, _) = extract_vote(vote)

        try:
            voter, voter_audit_codes = self.detect_voter(voter_key)
        except VoteRejectionError:
            # 's key not detected or not assigned any audit-codes
            raise
        if voter_secret:
            # Will reject vote if:
            # (1) no audit-code has been provided
            # (2) provided audit-code not among the assigned ones
            # (3) no audit-request found for the provided fingerprint
            # (4) vote failed to be verified as audit
            signature = self.submit_audit_vote(vote, voter_key, fingerprint,
                voter_audit_code, voter_audit_codes)
        else:
            # If no audit-code provided, choose one of the assigned ones
            # (Will reject vote if no audit-code has been provided
            # while skip-audit mode dispabled)
            voter_audit_code = self.fix_audit_code(voter_audit_code, voter_audit_codes)
            if voter_audit_code not in voter_audit_codes:
                # Will reject vote if audit-request already
                # submitted for the provided fingerprint
                signature = self.submit_audit_request(fingerprint, voter_key, vote)
            else:
                # Will reject vote if
                # (1) vote already cast
                # (2) vote limit reached
                # (3) vote failed to be validated
                signature = self.submit_genuine_vote(fingerprint, voter_key, vote)
        return signature

    # Submissions

    def submit_audit_request(self, fingerprint, voter_key, vote):
        """
        Raises VoteRejectionError if an audit-request has already been
        submitted for the inscribed fingerprint.
        Otherwise: modifies the vote's status to audit-request, signs the vote
        and attach to it the signature, stores the audit-request, audit-vote
        and vote, and returns the signature
        """
        election = self.get_controller()

        if election.get_audit_request(fingerprint):
            err = "Audit-request for vote [%s] already submitted" % (fingerprint,)
            raise VoteRejectionError(err)

        # Modify status
        vote['status'] = V_AUDIT_REQUEST
        vote['previous'] = ''
        vote['index'] = None

        # Sign vote and attach signature
        comments = self.custom_audit_request_message(vote)
        signature = election.sign_vote(vote, comments)
        vote['signature'] = signature

        # Store vote along with audit-request
        election.store_audit_request(fingerprint, voter_key)
        election.store_votes((vote,))

        return signature

    def submit_audit_vote(self, vote, voter_key, fingerprint,
            voter_audit_code, voter_audit_codes):
        """
        Raises VoteRejectionError if
            - No audit-code provided
            - Invalid audit-code provided
            - No prior audit-request found for publish-request
        """
        election = self.get_controller()

        # Check audit-publication prerequisites, reject otherwise
        if not voter_audit_code:
            err = "Invalid audit vote publication: No audit-code provided"
            raise VoteRejectionError(err)
        if voter_audit_code in voter_audit_codes:
            err = "Invalid audit vote publication: Invalid audit-code provided"
            raise VoteRejectionError(err)
        if voter_key != election.get_audit_request(fingerprint):
            err = "No prior audit-request found for publish-request"
            raise VoteRejectionError(err)

        # Audit-vote verification
        vote['status'] = V_PUBLIC_AUDIT
        vote['previous'] = ''
        vote['index'] = None
        missing, failed = election.validate_audit_votes((vote,))
        if missing:
            err = "Missing voter's secret: No randomness provided with audit-vote"
            raise VoteRejectionError(err)
        if failed:
            vote['status'] = V_PUBLIC_AUDIT_FAILED

        # Sign vote and attach signature
        comments = self.custom_audit_publication_message(vote)
        signature = election.sign_vote(vote, comments)
        vote['signature'] = signature

        # Append vote and store inscribed fingerprint as audit-publication
        fingerprint = vote['fingerprint']
        election.store_audit_publication(fingerprint)
        election.store_votes((vote,))

        return signature

    def submit_genuine_vote(self, fingerprint, voter_key, vote):
        """
        """
        election = self.get_controller()

        if election.get_vote(fingerprint):
            err = "Vote [%s] already cast" % (fingerprint,)
            raise VoteRejectionError(err)
        voter_cast_votes = election.get_voter_cast_votes(voter_key)
        vote_limit = election.get_option('vote_limit')
        if vote_limit and len(voter_cast_votes) >= vote_limit:
            err = "Maximum number of votes reached: %s" % vote_limit
            raise VoteRejectionError(err)

        if not voter_cast_votes:
            previous_fingerprint = ''
        else:
            previous_fingerprint = voter_cast_votes[-1]
        try:
            election.validate_genuine_vote(vote)
        except InvalidVoteError as err:
            raise VoteRejectionError(err)

        vote['status'] = V_CAST_VOTE
        vote['previous'] = previous_fingerprint
        vote['index'] = election.do_index_vote(fingerprint)

        # Sign vote and attach signature
        comments = self.custom_cast_vote_message(vote)
        signature = election.sign_vote(vote, comments)
        vote['signature'] = signature

        election.append_vote(voter_key, fingerprint)
        election.store_votes((vote,))

        ##################################################################
        # DANGER: commit all data to disk before giving a signature out! #
        ##################################################################
        return signature


    #  fixation

    def detect_voter(self, voter_key):
        """
        Reject vote if the provided key could not be detected
        Abort election if key was detected but no audit-codes correspond to it
        Return voter and audit-codes otherwise
        """
        election = self.get_controller()

        voter = election.get_voter(voter_key)
        voter_audit_codes = election.get_voter_audit_codes(voter_key)
        if not voter:
            err = 'Invalid voter key'
            raise VoteRejectionError()
        elif not voter_audit_codes:
            err = ' audit-codes inconsistency'
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
        election = self.get_controller()

        if not voter_audit_code:
            skip_audit = election.get_option('skip_audit')
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
