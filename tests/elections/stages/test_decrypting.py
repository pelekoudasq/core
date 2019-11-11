import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import mk_election

from zeus_core.elections.exceptions import Abortion

import unittest

class TestDecrypting(StageTester, unittest.TestCase):

    # Context implementation
    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        election.run_until_decrypting_stage()
        election.load_current_context()
        cls.stage = election._get_current_stage()

    # ------------------------ Isolated functionalities ------------------------

    def test_decrypt_ballots(self):
        pass

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Decrypting =================')
    time.sleep(.6)
    unittest.main()
