import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import run_until_finished_stage, mk_election

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized

import unittest

class TestFinished(StageTester, unittest.TestCase):

    # Context implementation
    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        run_until_finished_stage(election)
        election.load_current_context()
        cls.stage = election._get_current_stage()

    # ------------------------ Isolated functionalities ------------------------

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Finished ==================')
    time.sleep(.6)
    unittest.main()
