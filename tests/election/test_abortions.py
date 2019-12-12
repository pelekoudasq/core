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
        with self.assertRaises(Abortion):
            election = mk_election(config=config_2)
            election.run_until_creating_stage()
        messages.append(success_msg + ': Non prime modulus')


    def test_Abortion_upon_non_3_mod_4(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(config=config_3)
            election.run_until_creating_stage()
        messages.append(success_msg + ': Modulus is not 3 mod 4')


    def test_Abortion_upon_WrongMixnetError(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(config=config_4)
            election.run_until_creating_stage()
        messages.append(success_msg + ': Malformed parameters for Zeus SK')


    def test_Abortion_upon_InvalidTrusteeError(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(config=config_5)
            election.run_until_voting_stage()
        messages.append(success_msg + ': Trustee failed to validate themselves')


    def test_Abortion_upon_InvalidCandidateError(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(config=config_6)
            election.run_until_voting_stage()
        messages.append(success_msg + ': Duplicate candidate detected')


    def test_Abortion_upon_InvalidVoterError(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(config=config_7)
            election.run_until_voting_stage()
        messages.append(success_msg + ': Duplicate voter names')


    def test_Abortion_upon_InvalidFactorError(self):
        messages = __class__.messages
        with self.assertRaises(Abortion):
            election = mk_election(dishonest_trustee=True)
            election.run_until_finished_stage()
        messages.append(success_msg + ': Factors could not be verified')


if __name__ == '__main__':
    unittest.main()
