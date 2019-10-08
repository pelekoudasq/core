import time
import pytest
from copy import deepcopy
import sys


from tests.constants import _2048_SYSTEM
from tests.elections.stages.utils import create_election, run_until_uninitialized_stage

from zeus_core.elections.stages import Uninitialized

from zeus_core.crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from zeus_core.elections.exceptions import Abortion

import unittest

def get_cls_name(obj):
    return obj.__class__.__name__

class TestUninitialized(unittest.TestCase):

    # Setup

    def launch_election(self):
        election = create_election()
        self.election = election

    def run_until_stage(self):
        self.launch_election()
        self.uninitialized = Uninitialized(self.election)

    def setUp(self):
        self.run_until_stage()
        self.messages = []

    def tearDown(self):
        if self.messages:
            for i, message in enumerate(self.messages):
                if i == 0:
                    print('\n' + message)
                else:
                    print(message)


    # Cryptosys initialization

    def test_init_cryptosys(self):
        config = self.election.config
        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        cryptosys = self.uninitialized.init_cryptosys(crypto_cls, crypto_config)

        assert _2048_SYSTEM.parameters() == cryptosys.parameters()
        self.messages.append('[+] Successfully initialized: cryptosystem: %s'
            % get_cls_name(cryptosys))

    def mk_init_cryptosys_abort_cases(self):
        config = self.election.config
        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']

        abort_cases = [{
            'case': [crypto_cls, deepcopy(crypto_config)],
            'message': None
        } for _ in range(2)]

        abort_cases[0]['case'][1]['modulus'] += 1
        abort_cases[0]['message'] = "Wrong crypto: Non-prime modulus"

        abort_cases[1]['case'][1]['modulus'] = 7
        abort_cases[1]['message'] = "Weak crypto: Small modulus"

        return abort_cases

    def test_init_cryptosys_abort_cases(self):
        abort_cases = self.mk_init_cryptosys_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    self.uninitialized.init_cryptosys(cls, config)
                self.messages.append('[+] Successfully aborted: %s' % message)


    # Mixnet initialization

    def test_init_mixnet(self):
        config = self.election.config

        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']
        cryptosys = self.uninitialized.init_cryptosys(crypto_cls, crypto_config)

        mixnet = self.uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
        assert mixnet.parameters() == {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],
        }
        self.messages.append('[+] Successfully initialized: mixnet: %s'
            % get_cls_name(mixnet))

    def mk_init_mixnet_abort_cases(self):
        config = self.election.config

        class PseudoMixnet(object):
            def update(self, *args): pass
        pseudo_config = {'nr_mixes': 1}

        abort_cases = [
            {
                'case': (PseudoMixnet, config['mixnet']['config']),
                'message': 'Unsupported mixnet',
            },
            {
                'case': (config['mixnet']['cls'], pseudo_config),
                'message': 'Insufficient config'
            }
        ]
        return abort_cases


    def test_init_mixnet_abort_cases(self):
        config = self.election.config

        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']
        cryptosys = self.uninitialized.init_cryptosys(crypto_cls, crypto_config)

        abort_cases = self.mk_init_mixnet_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    self.uninitialized.init_mixnet(cls, config, cryptosys)
                self.messages.append('[+] Successfully aborted: %s' % message)


    # Run whole stage and check updates

    def step_0(self):
        election = self.election
        try:
            assert self.election._get_current_stage() is self.uninitialized
            self.messages.append('[+] Current stage: Uninitialized')
        except AssertionError:
            err = "Wrong election stage"
            raise AssertionError(err)

    def step_1(self):
        self.messages.append('\nBefore running:\n')

        cryptosys = self.election.get_cryptosys()
        awaited = None
        try:
            assert cryptosys == awaited
            self.messages.append('[+] cryptosys: %s' % cryptosys)
        except AssertionError:
            err = "Cryptosys was not: %s" % awaited
            self.messages.append('[-] %s\n' % err)
            raise AssertionError(err)

        crypto_params = self.election.get_crypto_params()
        awaited = {}
        try:
            assert crypto_params == awaited
            self.messages.append('[+] crypto_params: %s' % crypto_params)
        except AssertionError:
            err = "Crypto params were not: %s" % awaited
            self.messages.append('[-] %s\n' % err)
            raise AssertionError(err)

        mixnet = self.election.get_cryptosys()
        awaited = None
        try:
            assert mixnet == awaited
            self.messages.append('[+] mixnet: %s' % mixnet)
        except AssertionError:
            err = "Mixnet was not: %s" % awaited
            self.messages.append('[-] %s\n' % err)
            raise AssertionError(err)

    def step_2(self):
        self.uninitialized.run()
        self.messages.append('\nAfter running:\n')

        cryptosys = self.election.get_cryptosys()
        awaited = _2048_SYSTEM.parameters()
        try:
            assert cryptosys.parameters() == awaited
            self.messages.append('[+] cryptosys: ok')
        except AssertionError:
            err = "Wrong cryptosystem"
            self.messages.append('[-] %s\n' % err)
            raise AssertionError(err)


        crypto_params = self.election.get_crypto_params()
        awaited = _2048_SYSTEM.parameters()
        try:
            assert crypto_params == awaited
            self.messages.append('[+] crypto_params: ok')
        except AssertionError:
            err = "Crypto params were not: %s" % awaited
            raise AssertionError(err)

        mixnet = self.election.get_mixnet()
        mixnet_config = self.election.config['mixnet']['config']
        awaited = {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],
        }
        try:
            assert mixnet.parameters() == awaited
            self.messages.append('[+] mixnet: ok')
        except AssertionError:
            err = "Wrong mixnet"
            self.messages.append('[-] %s\n' % err)
            raise AssertionError(err)

    def stage_steps(self):
        for name in self.__dir__():
            if name.startswith('step_'):
                yield name, getattr(self, name)

    def test_run(self):
        print('\n')
        print('----------------------------- Run stage ------------------------------')
        for name, step in self.stage_steps():
            try:
                step()
            except AssertionError as err:
                self.fail("\n\nFAIL: {}: {}".format(name, err))

if __name__ == '__main__':
    print('\n=============== Testing election stage: Uninitialized ================')
    time.sleep(.6)
    unittest.main()
