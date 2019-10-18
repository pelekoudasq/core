import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import run_until_voting_stage

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized

import unittest

class TestVoting(StageTester, unittest.TestCase):

    # Context implementation

    def run_until_stage(self):
        self.launch_election()
        run_until_voting_stage(self.election)
        self.stage = self.election._get_current_stage()


    # ------------------------ Isolated functionalities ------------------------

    # ------------------------- Overall stage testing --------------------------


    def step_1(self):
        election, _, _ = self.get_context()
        self.append_message('\nBefore running:\n')

        cast_vote_index = election.get_cast_vote_index()
        awaited = []
        try:
            assert cast_vote_index == awaited
            self.append_message('[+] cast_vote_index: %s' % cast_vote_index)
        except AssertionError:
            err = "Cast vote index was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        votes = election.get_votes()
        awaited = None
        try:
            assert votes == {}
            self.append_message('[+] votes: %s' % votes)
        except AssertionError:
            err = "Votes were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        cast_votes = election.get_cast_votes()
        awaited = {}
        try:
            assert cast_votes == awaited
            self.append_message('[+] cast_votes: %s' % cast_votes)
        except AssertionError:
            err = "Cast votes were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        audit_requests = election.get_audit_requests()
        awaited = {}
        try:
            assert audit_requests == awaited
            self.append_message('[+] audit_requests: %s' % audit_requests)
        except AssertionError:
            err = "Audit requests were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        audit_votes = election.get_audit_votes()
        awaited = {}
        try:
            assert audit_votes == awaited
            self.append_message('[+] audit_votes: %s' % audit_requests)
        except AssertionError:
            err = "Audit votes were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        audit_publications = election.get_audit_publications()
        awaited = []
        try:
            assert audit_publications == awaited
            self.append_message('[+] audit_publications: %s' % audit_publications)
        except AssertionError:
            err = "Audit publications were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        excluded_voters = election.get_excluded_voters()
        awaited = {}
        try:
            assert excluded_voters == awaited
            self.append_message('[+] excluded_voters: %s' % excluded_voters)
        except AssertionError:
            err = "Excluded voters were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)


if __name__ == '__main__':
    print('\n=================== Testing election stage: Voting ===================')
    time.sleep(.6)
    unittest.main()
