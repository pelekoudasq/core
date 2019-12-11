import pytest
from copy import deepcopy
import time

from tests.election.stages.abstracts import StageTester
from tests.election.makers import mk_election

from zeus_core.election.exceptions import Abortion

import unittest

class TestDecrypting(StageTester, unittest.TestCase):


    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        election.run_until_decrypting_stage()
        cls.stage = election._get_current_stage()

    # ------------------------ Isolated functionalities ------------------------

    def test_decrypt_ballots(self):
        pass

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Decrypting =================')
    time.sleep(.6)
    unittest.main()
