import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester
from tests.elections.utils import run_until_decrypting_stage

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized


import unittest

class TestDecrypting(StageTester, unittest.TestCase):

    # Setup

    def run_until_stage(self):
        self.launch_election()
        run_until_decrypting_stage(self.election)
        self.stage = self.election._get_current_stage()

    # ------------------------ Isolated functionalities ------------------------

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Decrypting =================')
    time.sleep(.6)
    unittest.main()
