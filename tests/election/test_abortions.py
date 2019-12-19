"""
"""

import unittest

from tests.election.makers import mk_election
from zeus_core.election.exceptions import Abortion
from tests.election.emulators.election_configs import (
    config_1, config_2, config_3, config_4, config_5, config_6, config_7)


success_msg = '[+] Election successfully aborted'

class TestAbortions(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        cls.messages = []

    @classmethod
    def tearDownClass(cls):
        print('\n')
        for message in cls.messages:
            print(message)


    def test_Abortion_upon_non_prime_modulus(self):
        messages = __class__.messages
        election = mk_election(config=config_2)
        uninitialized = election.run_until_uninitialized_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                uninitialized.run()
            messages.append(success_msg + ': Non prime modulus')
        with self.subTest():
            assert election._get_exports() == {}


    def test_Abortion_upon_non_3_mod_4(self):
        messages = __class__.messages
        election = mk_election(config=config_3)
        uninitialized = election.run_until_uninitialized_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                uninitialized.run()
            messages.append(success_msg + ': Modulus is not 3 mod 4')
        with self.subTest():
            assert election._get_exports() == {}


    def test_Abortion_upon_WrongMixnetError(self):
        messages = __class__.messages
        election = mk_election(config=config_4)
        uninitialized = election.run_until_uninitialized_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                uninitialized.run()
            messages.append(success_msg + ': Malformed parameters for Zeus SK')
        with self.subTest():
            assert election._get_exports() == {}


    def test_Abortion_upon_InvalidTrusteeError(self):
        messages = __class__.messages
        election = mk_election(config=config_5)
        creating = election.run_until_creating_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                creating.run()
            messages.append(success_msg + ': Trustee failed to validate themselves')
        with self.subTest():
            assert election._get_exports() == {
                    'cryptosystem': election.get_crypto_hex(),
                    'mixnet': election.get_mixnet_type(),
                }


    def test_Abortion_upon_InvalidCandidateError(self):
        messages = __class__.messages
        election = mk_election(config=config_6)
        creating = election.run_until_creating_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                creating.run()
            messages.append(success_msg + ': Duplicate candidate detected')
        with self.subTest():
            assert election._get_exports() == {
                    'cryptosystem': election.get_crypto_hex(),
                    'mixnet': election.get_mixnet_type(),
                }


    def test_Abortion_upon_InvalidVoterError(self):
        messages = __class__.messages
        election = mk_election(config=config_7)
        creating = election.run_until_creating_stage()
        with self.subTest():
            with self.assertRaises(Abortion):
                creating.run()
            messages.append(success_msg + ': Duplicate voter names')
        with self.subTest():
            assert election._get_exports() == {
                    'cryptosystem': election.get_crypto_hex(),
                    'mixnet': election.get_mixnet_type(),
                }


    def test_Abortion_upon_InvalidFactorError(self):
        messages = __class__.messages
        election = mk_election(dishonest_trustee=True)
        voting = election.run_until_voting_stage()
        election._run(voting)
        serialized_votes = voting.serialized_votes
        serialized_audit_requests = voting.serialized_audit_requests
        serialized_audit_publications = voting.serialized_audit_publications
        mixing = voting.next()
        election._run(mixing)
        decrypting = mixing.next()
        with self.subTest():
            with self.assertRaises(Abortion):
                decrypting.run()
            messages.append(success_msg + ': Factors could not be verified')
        with self.subTest():
            assert election._get_exports() == {
                    'cryptosystem': election.get_crypto_hex(),
                    'mixnet': election.get_mixnet_type(),
                    'zeus_public': election.get_hex_zeus_public_key(),
                    'zeus_key_proof': election.get_hex_zeus_key_proof(),
                    'trustees': election.get_trustees_serialized(),
                    'election_key': election.get_election_key_serialized(),
                    'candidates': election.get_candidates(),
                    'voters': election.get_voters(),
                    'audit_codes': election.get_audit_codes(),
                    'votes': serialized_votes,
                    'cast_vote_index': election.get_cast_vote_index(),
                    'cast_votes': election.get_cast_votes(),
                    'audit_requests': serialized_audit_requests,
                    'audit_publications': serialized_audit_publications,
                    'excluded_voters': election.get_excluded_voters(),
                    'mixes': election.do_get_all_mixes()[1:],
                }


if __name__ == '__main__':
    unittest.main()
