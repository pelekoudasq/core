import pytest
from copy import deepcopy
import time

from tests.election.stages.abstracts import StageTester
from tests.election.makers import mk_election

from zeus_core.election.exceptions import Abortion

import unittest

class TestFinished(StageTester, unittest.TestCase):


    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        election.run_until_finished_stage()
        cls.stage = election.get_current_stage()

    # ------------------------ Isolated functionalities ------------------------

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Finished ==================')
    time.sleep(.6)
    unittest.main()
