import pytest
import unittest
import sys
from copy import deepcopy
import time

from zeus_core.crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from tests.constants import _2048_SYSTEM
from tests.election.makers import mk_election
from tests.election.stages.abstracts import StageTester, get_cls_name


class TestUninitialized(StageTester, unittest.TestCase):


    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        election.run_until_uninitialized_stage()
        cls.stage = election._get_current_stage()


    # Cryptosystem initialization

    def test_init_cryptosys(self):
        election, _, _, messages = self.get_context()
        election.init_cryptosys()
        cryptosys = election.get_cryptosys()
        assert _2048_SYSTEM.parameters() == cryptosys.parameters()
        messages.append(
            f'[+] Successfully initialized: Cryptosystem: {get_cls_name(cryptosys)}')


    # Mixnet initialization

    def test_init_mixnet(self):
        election, _, _, messages = self.get_context()
        election.init_cryptosys()
        mixnet_config = election.get_mixnet_config()
        election.init_mixnet()
        cryptosys = election.get_cryptosys()
        mixnet = election.get_mixnet()
        assert mixnet.get_config() == {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],}
        messages.append(f'[+] Successfully initialized: Mixnet: {get_cls_name(mixnet)}')


if __name__ == '__main__':
    print('\n================ Testing election stage: Uninitialized ================')
    time.sleep(.6)
    unittest.main()
