"""
"""

import unittest

from tests.election.makers import mk_election
from zeus_core.election.exceptions import Abortion


class TestSuccess(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        election = mk_election()
        cls.election = election

    @classmethod
    def tearDownClass(cls):
        print('\n')
        for message in cls.messages:
            print(message)

    def get_election(self):
        return __class__.election

    # def test_0_uninitialized(selfl):
    #     assert self.get_election() is not None
    #
    # def test_1_creating(self):
    #     pass
    #
    # def test_2_voting(self):
    #     pass
    #
    # def test_3_mixing(self):
    #     pass
    #
    # def test_4_decrypting(self):
    #     pass
    #
    # def test_5_finished(self):
    #     pass
