import time
import pytest
from copy import deepcopy
import sys

from tests.elections.stages.abstracts import StageTester
from tests.constants import _2048_SYSTEM

from zeus_core.elections.stages import Uninitialized
from zeus_core.crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from zeus_core.elections.exceptions import Abortion

import unittest

def get_cls_name(obj):
    return obj.__class__.__name__

class TestUninitialized(StageTester, unittest.TestCase):

    # Context implementation

    def run_until_stage(self):
        self.launch_election()
        self.stage = Uninitialized(self.election)


    # ------------------------ Isolated functionalities ------------------------

    # Cryptosys initialization

    def test_init_cryptosys(self):
        _, config, uninitialized = self.get_context()

        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)

        assert _2048_SYSTEM.parameters() == cryptosys.parameters()
        self.append_message('[+] Successfully initialized: cryptosystem: %s'
            % get_cls_name(cryptosys))

    def mk_init_cryptosys_abort_cases(self):
        _, config, _ = self.get_context()

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
        _, _, uninitialized = self.get_context()

        abort_cases = self.mk_init_cryptosys_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    uninitialized.init_cryptosys(cls, config)
                self.append_message('[+] Successfully aborted: %s' % message)


    # Mixnet initialization

    def test_init_mixnet(self):
        _, config, uninitialized = self.get_context()

        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)

        mixnet = uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
        assert mixnet.parameters() == {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],}
        self.append_message('[+] Successfully initialized: mixnet: %s'
            % get_cls_name(mixnet))

    def mk_init_mixnet_abort_cases(self):
        _, config, _ = self.get_context()

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
        _, config, uninitialized = self.get_context()

        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)

        abort_cases = self.mk_init_mixnet_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    uninitialized.init_mixnet(cls, config, cryptosys)
                self.append_message('[+] Successfully aborted: %s' % message)


    # ------------------------- Overall stage testing --------------------------

    def step_1(self):
        election, _, _ = self.get_context()
        self.append_message('\nBefore running:\n')

        cryptosys = election.get_cryptosys()
        crypto_params = election.get_crypto_params()
        mixnet = election.get_mixnet()

        awaited = None
        try:
            assert cryptosys == awaited
            self.append_message('[+] cryptosys: %s' % cryptosys)
        except AssertionError:
            err = "Cryptosys was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        awaited = {}
        try:
            assert crypto_params == awaited
            self.append_message('[+] crypto_params: %s' % crypto_params)
        except AssertionError:
            err = "Crypto params were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        awaited = None
        try:
            assert mixnet == awaited
            self.append_message('[+] mixnet: %s' % mixnet)
        except AssertionError:
            err = "Mixnet was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

    def step_2(self):
        election, config, uninitialized = self.get_context()

        uninitialized.run()
        self.append_message('\nAfter running:\n')

        cryptosys = election.get_cryptosys()
        crypto_params = election.get_crypto_params()
        mixnet_config = config['mixnet']['config']
        mixnet = election.get_mixnet()

        awaited = _2048_SYSTEM.parameters()
        try:
            assert cryptosys.parameters() == awaited
            self.append_message('[+] cryptosys: ok')
        except AssertionError:
            err = "Wrong cryptosystem"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        awaited = _2048_SYSTEM.parameters()
        try:
            assert crypto_params == awaited
            self.append_message('[+] crypto_params: ok')
        except AssertionError:
            err = "Crypto params were not: %s" % awaited
            raise AssertionError(err)

        awaited = {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],}
        try:
            assert mixnet.parameters() == awaited
            self.append_message('[+] mixnet: ok')
        except AssertionError:
            err = "Wrong mixnet"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)


if __name__ == '__main__':
    print('\n=============== Testing election stage: Uninitialized ================')
    time.sleep(.6)
    unittest.main()
