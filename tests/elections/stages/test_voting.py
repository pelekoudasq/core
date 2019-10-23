import pytest
import unittest
from copy import deepcopy
import time

from zeus_core.elections.stages import Uninitialized
from zeus_core.elections.utils import extract_vote
from zeus_core.elections.exceptions import Abortion

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import mk_voting_setup, display_json


class TestVoting(StageTester, unittest.TestCase):

    # Context implementation
    @classmethod
    def run_until_stage(cls):
        election, _, votes = mk_voting_setup()
        cls.election = election
        cls.stage = election._get_current_stage()
        cls.votes = votes

    def get_voting_context(self):
        """
        Enhance context of voting stage with votes
        """
        election, config, stage, messages = self.get_context()
        votes = self.votes
        return election, config, stage, votes, messages



    # ------------------------ Isolated functionalities ------------------------

    def test_detect_voter(self):
        pass

    def test_fix_audit_code(self):
        pass

    def test_exclude_voter(self):
        pass

    def test_vote_adaptment_success(self):
        pass

    def test_vote_adaptment_rejections(self):
        pass

    def test_submit_audit_request_success(self):
        pass

    def test_submit_audit_request_rejection(self):
        pass

    def test_submit_audit_vote_success(self):
        pass

    def test_submit_audit_vote_rejection(self):
        pass

    def test_submit_genuine_vote_success(self):
        _, _, voting, votes, _ = self.get_voting_context()
        for vote in votes:
            vote = voting.adapt_vote(deepcopy(vote))
            (_, _, voter_key, _, fingerprint, _, _, _, _, _, _) = extract_vote(vote)
            voting.submit_genuine_vote(fingerprint, voter_key, vote)

    def test_submit_genuine_vote_rejection(self):
        pass

    def test_cast_vote_success(self):
        pass

    def test_cast_vote_rejection(self):
        pass

    # ------------------------- Overall stage testing --------------------------


    def step_1(self):
        election, _, _, messages = self.get_context()
        messages.append('\nBefore running:\n')

        cast_vote_index = election.get_cast_vote_index()
        awaited = []
        try:
            assert cast_vote_index == awaited
            messages.append(f'[+] cast_vote_index: {cast_vote_index}')
        except AssertionError:
            err = 'Cast vote index was not: {awaited}'
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


if __name__ == '__main__':
    print('\n=================== Testing election stage: Voting ===================')
    time.sleep(.6)
    unittest.main()
