import pytest
import unittest
from copy import deepcopy
import time

from zeus_core.elections.utils import extract_vote
from zeus_core.elections.exceptions import Abortion, VoteRejectionError

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import mk_voting_setup, display_json


class TestVoting(StageTester, unittest.TestCase):

    # Context implementation
    @classmethod
    def run_until_stage(cls):
        election, _, votes, audit_requests, audit_votes = \
            mk_voting_setup(with_votes=True)
        cls.election = election
        election.load_current_context()
        cls.stage = election._get_current_stage()
        cls.votes = votes
        cls.audit_requests = audit_requests
        cls.audit_votes = audit_votes

    def get_voting_context(self):
        """
        Extends voting stage context with votes and audit-requests
        """
        election, config, stage, messages = self.get_context()
        votes = list(map(deepcopy, self.votes))
        audit_requests = list(map(deepcopy, self.audit_requests))
        audit_votes = list(map(deepcopy, self.audit_votes))
        return (election, config, stage,
            votes, audit_requests, audit_votes, messages,)

    def clear_election(self):
        election, _, _, _ = self.get_context()
        election.audit_requests = {}
        election.audit_votes = {}
        election.audit_publications = []
        election.cast_vote_index = []
        election.votes = {}
        election.cast_votes = {}
        election.excluded_voters = {}


    # ------------------------ Isolated functionalities ------------------------


    def test_0_submit_audit_request(self):
        election, _, voting, _, audit_requests, _, messages = \
            self.get_voting_context()
        messages.append('\nTesting audit-requst submission\n')
        submit_audit_request = voting.submit_audit_request
        get_audit_request = election.get_audit_request
        get_vote = election.get_vote
        for vote in audit_requests:
            vote = deepcopy(vote)
            with self.subTest(vote=vote):
                vote = election.adapt_vote(vote)
                (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                    extract_vote(vote)
                submit_audit_request(fingerprint, voter_key, vote)
                assert (get_audit_request(fingerprint) is voter_key and \
                    get_vote(fingerprint) is vote)
                messages.append('[+] Audit-request successfully submitted')

        # Test rejection of already submitted request
        with self.subTest(vote=audit_requests[0]):
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                extract_vote(vote)
            with self.assertRaises(VoteRejectionError):
                submit_audit_request(fingerprint, voter_key, vote)
            messages.append('[+] Audit-request successfully rejected')


    def test_2_submit_audit_vote_success(self):
        election, _, voting, _, _, audit_votes, messages = \
            self.get_voting_context()
        messages.append('\nTesting audit-vote submission on success\n')
        submit_audit_vote = voting.submit_audit_vote
        get_audit_publications = election.get_audit_publications
        get_vote = election.get_vote
        for vote in audit_votes:
            vote = deepcopy(vote)
            with self.subTest(vote=vote):
                vote = election.adapt_vote(vote)
                (_, _, voter_key, _, fingerprint, voter_audit_code, \
                    _, _, _, _, _) = extract_vote(vote)
                voter_audit_codes = election.get_voter_audit_codes(voter_key)
                submit_audit_vote(vote, voter_key, fingerprint,
                    voter_audit_code, voter_audit_codes)
                assert (fingerprint in get_audit_publications() and \
                    get_vote(fingerprint) is vote)
                messages.append('[+] Audit-vote successfully submitted')


    def test_3_submit_audit_vote_rejection(self):
        election, _, voting, _, _, audit_votes, messages = \
            self.get_voting_context()
        messages.append('\nTesting audit-vote submission on failure\n')

        votes_and_messages = []

        # No audit-code provided
        vote_0 = deepcopy(audit_votes[0])
        del vote_0['audit_code']
        votes_and_messages.append((
            vote_0,
            '[+] Missing audit-code: Successfully rejected',
        ))
        # Invalid audit-code provided
        vote_1 = deepcopy(audit_votes[1])
        voter_key = vote_1['voter']
        voter_audit_codes = election.get_voter_audit_codes(voter_key)
        vote_1['audit_code'] = voter_audit_codes[0]
        votes_and_messages.append((
            vote_1,
            '[+] Invalid audit-code: Successfully rejected',
        ))
        # No prior audit-requst
        vote_2 = deepcopy(audit_votes[2])
        vote_2['fingerprint'] += '0'
        votes_and_messages.append((
            vote_2,
            '[+] No prior request: Successfully rejected',
        ))
        # Missing voter's secret
        vote_3 = deepcopy(audit_votes[3])
        del vote_3['voter_secret']
        votes_and_messages.append((
            vote_3,
            '[+] Missing secret: Successfully rejected',
        ))

        submit_audit_vote = voting.submit_audit_vote
        for vote, success_msg in votes_and_messages:
            with self.subTest(vote=vote):
                vote = election.adapt_vote(vote)
                (_, _, voter_key, _, fingerprint, voter_audit_code, \
                    _, _, _, _, _) = extract_vote(vote)
                voter_audit_codes = election.get_voter_audit_codes(voter_key)
                with self.assertRaises(VoteRejectionError):
                    submit_audit_vote(vote, voter_key, fingerprint,
                        voter_audit_code, voter_audit_codes)
                messages.append(success_msg)


    def test_4_submit_genuine_vote(self):
        self.clear_election()
        election, _, voting, votes, _, _, messages = \
            self.get_voting_context()
        messages.append('\nTesting genuine vote submission\n')
        submit_genuine_vote = voting.submit_genuine_vote
        get_voter_cast_votes = election.get_voter_cast_votes
        get_vote = election.get_vote
        for vote in votes:
            with self.subTest(vote=vote):
                vote = deepcopy(vote)
                vote = election.adapt_vote(vote)
                (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                    extract_vote(vote)
                submit_genuine_vote(fingerprint, voter_key, vote)
                assert (fingerprint in get_voter_cast_votes(voter_key) and \
                    get_vote(fingerprint) is vote)
                messages.append('[+] Vote successfully submitted')

        # Test rejection of already submitted vote
        with self.subTest(vote=votes[0]):
            vote = deepcopy(vote)
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                extract_vote(vote)
            with self.assertRaises(VoteRejectionError):
                submit_genuine_vote(fingerprint, voter_key, vote)
            messages.append('[+] Submitted vote: Successfully rejected')

        # Test rejection upon vote limit
        election.options['vote_limit'] = 1
        with self.subTest(vote=votes[0]):
            vote = deepcopy(vote)
            vote['fingerprint'] += '0'
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                extract_vote(vote)
            with self.assertRaises(VoteRejectionError):
                submit_genuine_vote(fingerprint, voter_key, vote)
            messages.append('[+] Vote limit reached: Successfully rejected')
        del election.options['vote_limit']

        # Test rejection upon invalidity
        with self.subTest(vote=votes[0]):
            vote = deepcopy(vote)
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                extract_vote(vote)
            vote['public'] += 1
            with self.assertRaises(VoteRejectionError):
                submit_genuine_vote(fingerprint, voter_key, vote)
            messages.append('[+] Invalid vote: Successfully rejected')


    def test_6_cast_vote_success(self):
        self.clear_election()
        (election, _, voting, votes, audit_requests,
            audit_votes, messages) = self.get_voting_context()
        messages.append('\nTesting vote casting on success\n')
        cast_vote = voting.cast_vote
        for vote in audit_requests:
            with self.subTest(vote=vote):
                cast_vote(vote)
                messages.append('[+] Audit-request successfully cast')
        for vote in audit_votes:
            with self.subTest(vote=vote):
                cast_vote(vote)
                messages.append('[+] Audit-vote successfully cast')
        for vote in votes[:-1]:
            with self.subTest(vote=vote):
                cast_vote(vote)
                messages.append('[+] Vote successfully cast')

    def test_7_cast_vote_rejection(self):
        self.clear_election()
        (election, _, voting, votes, _,
            audit_votes, messages) = self.get_voting_context()
        messages.append('\nTesting vote casting on failure\n')

        vote = votes[0]
        with self.subTest(vote=vote):
            del vote['voter']
            with self.assertRaises(VoteRejectionError):
                voting.cast_vote(vote)
            messages.append('[+] Vote successfully rejected: missing fields')

        vote = votes[1]
        with self.subTest(vote=vote):
            voter = vote['voter']
            (voter_name, voter_weight) = election.voters[voter]
            del election.voters[voter]
            with self.assertRaises(VoteRejectionError):
                voting.cast_vote(vote)
            messages.append('[+] Vote successfully rejected: voter not detected')
            election.voters[voter] = (voter_name, voter_weight) # restore election

        audit_vote = audit_votes[0]
        with self.subTest(audit_vote=audit_vote):
            del audit_vote['audit_code']
            with self.assertRaises(VoteRejectionError):
                voting.cast_vote(vote)
            messages.append('[+] Audit-vote successfully rejected: no audit-code provided')


    # ------------------------- Overall stage testing --------------------------


    def step_1(self):
        self.clear_election()

        election, _, _, messages = self.get_context()
        messages.append('\nBefore running:\n')

        cast_vote_index = election.get_cast_vote_index()
        awaited = []
        try:
            assert cast_vote_index == awaited
            messages.append(f'[+] cast_vote_index: {cast_vote_index}')
        except AssertionError:
            err = f'Cast vote index was not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        votes = election.get_votes()
        awaited = None
        try:
            assert votes == {}
            messages.append(f'[+] votes: {votes}')
        except AssertionError:
            err = f'Votes were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        cast_votes = election.get_cast_votes()
        awaited = {}
        try:
            assert cast_votes == awaited
            messages.append(f'[+] cast_votes: {cast_votes}')
        except AssertionError:
            err = f'Cast votes were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        audit_requests = election.get_audit_requests()
        awaited = {}
        try:
            assert audit_requests == awaited
            messages.append(f'[+] audit_requests: {audit_requests}')
        except AssertionError:
            err = f'Audit requests were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        audit_votes = election.get_audit_votes()
        awaited = {}
        try:
            assert audit_votes == awaited
            messages.append(f'[+] audit_votes: {audit_requests}')
        except AssertionError:
            err = f'Audit votes were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        audit_publications = election.get_audit_publications()
        awaited = []
        try:
            assert audit_publications == awaited
            messages.append(f'[+] audit_publications: {audit_publications}')
        except AssertionError:
            err = f'Audit publications were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        excluded_voters = election.get_excluded_voters()
        awaited = {}
        try:
            assert excluded_voters == awaited
            messages.append(f'[+] excluded_voters: {excluded_voters}')
        except AssertionError:
            err = f'Excluded voters were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

    def step_2(self):
        election, _, voting, votes, _, _, messages = \
            self.get_voting_context()
        submit_genuine_vote = voting.submit_genuine_vote
        get_voter_cast_votes = election.get_voter_cast_votes
        get_vote = election.get_vote
        for vote in votes:
            vote = election.adapt_vote(vote)
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = \
                extract_vote(vote)
            submit_genuine_vote(fingerprint, voter_key, vote)



if __name__ == '__main__':
    print('\n=================== Testing election stage: Voting ===================')
    time.sleep(.6)
    unittest.main()
