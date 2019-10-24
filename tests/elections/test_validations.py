"""
Tests in standalone fashion the vote-validation interface
"""

import pytest
import json
import unittest
from zeus_core.elections.validations import Validator
from zeus_core.elections.exceptions import InvalidVoteError
from tests.elections.utils import display_json, mk_voting_setup, adapt_vote


class DummyValidator(Validator):
    """
    Minimal implementation of validations interface for testing purposes
    """
    def __init__(self, election):
        self.election = election
        self.cryptosys = election.get_cryptosys()

    def get_cryptosys(self):
        return self.cryptosys

    def get_crypto_params(self):
        return self.election.get_crypto_params()

    def get_election_key(self):
        return self.election.get_election_key()

    def get_candidates(self):
        return self.election.get_candidates()

    def get_audit_votes(self):
        return self.election.get_audit_votes()


class TestValidations(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        election, clients = mk_voting_setup()

        cls.election = election
        cls.cryptosys = election.get_cryptosys()
        cls.validator = DummyValidator(election)
        cls.client = clients[0]
        cls.messages = []

    @classmethod
    def tearDownClass(cls):
        messages = cls.messages
        for i, message in enumerate(messages):
            if i == 0:
                print('\n' + message)
            else:
                print(message)

    def get_context(self):
        cls = self.__class__
        election = cls.election
        cryptosys = cls.cryptosys
        validator = cls.validator
        client = cls.client
        messages = cls.messages

        return election, cryptosys, validator, client, messages

    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)


    def test_vote_adaptment_success(self):
        pass

    def test_vote_adaptment_failures(self):
        pass

    def test_genuine_vote_validation_success(self):
        _, cryptosys, validator, client, messages = self.get_context()

        vote = client.mk_genuine_vote()
        vote = adapt_vote(cryptosys, vote)
        try:
            validator.validate_genuine_vote(vote)
            messages.append('[+] Vote: Successfully validated')
        except InvalidVoteError:
            err = 'Valid vote erroneously invalidated'
            self.__fail(err)

    def test_genuine_vote_validation_failures(self):
        _, cryptosys, validator, client, messages = self.get_context()

        err = 'Invalid vote failed to be detected'
        for kwargs, msg in (
            ({'corrupt_proof': True}, 'invalid encryption'),
            ({'corrupt_fingerprint': True}, 'fingerprint mismatch'),
        ):
            vote = client.mk_genuine_vote(**kwargs)
            with self.subTest(vote=vote):
                vote = adapt_vote(cryptosys, vote)
                try:
                    validator.validate_genuine_vote(vote)
                except InvalidVoteError:
                    messages.append(f'[+] Vote: Invalid detected ({msg})')
                else:
                    self.__fail(f'{err} ({msg})')

    def test_audit_vote_validation_success(self):
        _, cryptosys, validator, client, messages = self.get_context()

        audit_vote = client.mk_audit_vote()
        audit_vote = adapt_vote(cryptosys, audit_vote)
        missing, failed = validator.validate_audit_votes(audit_votes=[audit_vote,])
        try:
            assert not missing and not failed
            messages.append('[+] Audit-vote: Successfully validated')
        except AssertionError:
            err = 'Valid audit-vote erroneously invalidated'
            self.__fail(err)

    def test_audit_vote_validation_failures(self):
        election, cryptosys, validator, client, messages = self.get_context()

        err = 'Invalid audit-vote failed to be detected'
        for kwargs, msg in (
            ({'missing': True}, 'missing secret'),
            ({'corrupt_proof': True}, 'invalid encryption'),
            ({'corrupt_alpha': True}, 'invalid secret'),
            ({'corrupt_encoding': True}, 'max-gamma exceeded'),
        ):
            if msg == 'max-gamma exceeded':
                # ~ Dramatically reduce the number of candidates so that
                # ~ decrypting the ballot with the voter's secret
                # ~ exceeds max-gamma encoding of their number
                save_candidates = election.get_candidates()
                election.set_candidates(save_candidates[:1])
                fake_nr_candidates = len(election.get_candidates())
                kwargs.update({'fake_nr_candidates': fake_nr_candidates})
            audit_vote = client.mk_audit_vote(**kwargs)
            with self.subTest(audit_vote=audit_vote):
                audit_vote = adapt_vote(cryptosys, audit_vote)
                missing, failed = validator.validate_audit_votes((audit_vote,))
                try:
                    if msg == 'missing secret':
                        assert missing == [audit_vote,] and not failed
                    else:
                        assert not missing and failed == [audit_vote,]
                    messages.append(f'[+] Audit-vote: Invalid detected ({msg})')
                except AssertionError:
                    self.__fail(f'{err} ({msg})')
                if msg == 'max-gamma exceeded':
                    election.set_candidates(save_candidates) # Restore for subsequent tests


if __name__ == '__main__':
    print('\n====================== Testing vote validations ======================')
    unittest.main()
