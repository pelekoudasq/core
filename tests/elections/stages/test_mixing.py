import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized


import unittest

class TestMixing(StageTester, unittest.TestCase):

    # Setup

    def run_until_stage(self):
        self.launch_election()
        uninitialized = Uninitialized(self.election)
        uninitialized.run()
        creating = uninitialized.next()
        creating.run()
        voting = creating.next()
        voting.run()
        self.mixing = voting.next()

    # ...

    # Run whole stage and check updates

if __name__ == '__main__':
    print('\n=================== Testing election stage: Mixing ===================')
    time.sleep(.6)
    unittest.main()
