import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized


import unittest

class TestFinalized(StageTester, unittest.TestCase):

    # Setup

    def run_until_stage(self):
        self.launch_election()
        uninitialized = Uninitialized(self.election)
        uninitialized.run()
        creating = uninitialized.next()
        creating.run()
        voting = creating.next()
        voting.run()
        mixing = voting.next()
        mixing.run()
        decrypting = voting.next()
        decrypting.run()
        finalized = decrypting.next()
        self.stage = finalized

    # ------------------------ Isolated functionalities ------------------------

    # ------------------------- Overall stage testing --------------------------

if __name__ == '__main__':
    print('\n================= Testing election stage: Finalized ==================')
    time.sleep(.6)
    unittest.main()
