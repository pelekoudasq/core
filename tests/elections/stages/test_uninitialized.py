import pytest
import unittest
import sys
from copy import deepcopy
import time

from zeus_core.elections.stages import Uninitialized
from zeus_core.crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from zeus_core.elections.exceptions import Abortion
from tests.constants import _2048_SYSTEM
from tests.elections.utils import run_until_uninitialized_stage, mk_election
from tests.elections.stages.abstracts import StageTester, get_cls_name


class TestUninitialized(StageTester, unittest.TestCase):

    # Context implementation
    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        run_until_uninitialized_stage(election)
        election.load_current_context()
        cls.stage = election._get_current_stage()


    # ------------------------ Isolated functionalities ------------------------

    # Cryptosystem initialization

    def test_init_cryptosys(self):
        _, config, uninitialized, messages = self.get_context()

        crypto_cls = config['crypto_cls']
        crypto_config = config['crypto_config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
        assert _2048_SYSTEM.parameters() == cryptosys.parameters()
        messages.append(
            f'[+] Successfully initialized: cryptosystem: {get_cls_name(cryptosys)}')


    def mk_init_cryptosys_abort_cases(self):
        _, config, _, _ = self.get_context()

        crypto_cls = config['crypto_cls']
        crypto_config = config['crypto_config']

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
        _, _, uninitialized, messages = self.get_context()

        abort_cases = self.mk_init_cryptosys_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    uninitialized.init_cryptosys(cls, config)
                messages.append(f'[+] Successfully aborted: {message}')


    # Mixnet initialization

    def test_init_mixnet(self):
        _, config, uninitialized, messages = self.get_context()

        crypto_cls = config['crypto_cls']
        crypto_config = config['crypto_config']
        mixnet_cls = config['mixnet_cls']
        mixnet_config = config['mixnet_config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
        mixnet = uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
        assert mixnet.get_config() == {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],}
        messages.append(f'[+] Successfully initialized: mixnet: {get_cls_name(mixnet)}')


    def mk_init_mixnet_abort_cases(self):
        _, config, _, _ = self.get_context()
        class PseudoMixnet(object):
            def update(self, *args): pass
        pseudo_config = {'nr_mixes': 1}
        abort_cases = [
            {
                'case': (PseudoMixnet, config['mixnet_config']),
                'message': 'Unsupported mixnet',
            },
            {
                'case': (config['mixnet_cls'], pseudo_config),
                'message': 'Insufficient config'
            }
        ]
        return abort_cases

    def test_init_mixnet_abort_cases(self):
        _, config, uninitialized, messages = self.get_context()

        crypto_cls = config['crypto_cls']
        crypto_config = config['crypto_config']
        mixnet_cls = config['mixnet_cls']
        mixnet_config = config['mixnet_config']
        cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
        abort_cases = self.mk_init_mixnet_abort_cases()
        for abort_case in abort_cases:
            cls, config = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, cls=cls, config=config):
                with self.assertRaises(Abortion):
                    uninitialized.init_mixnet(cls, config, cryptosys)
                messages.append(f'[+] Successfully aborted: {message}')


    # ------------------------- Overall stage testing --------------------------

    def step_1(self):
        election, _, _, messages = self.get_context()
        messages.append('\nBefore running:\n')

        cryptosys = election.get_cryptosys()
        crypto_params = election.get_crypto_params()
        mixnet = election.get_mixnet()

        awaited = None
        try:
            assert cryptosys == awaited
            messages.append(f'[+] cryptosys: {cryptosys}')
        except AssertionError:
            err = f'Cryptosys was not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        awaited = {}
        try:
            assert crypto_params == awaited
            messages.append(f'[+] crypto_params: {crypto_params}')
        except AssertionError:
            err = f'Crypto params were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        awaited = None
        try:
            assert mixnet == awaited
            messages.append('[+] mixnet: %s' % mixnet)
        except AssertionError:
            err = f'Mixnet was not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

    def step_2(self):
        election, config, uninitialized, messages = self.get_context()

        uninitialized.run()
        messages.append('\nAfter running:\n')

        cryptosys = election.get_cryptosys()
        crypto_params = election.get_crypto_params()
        mixnet_config = config['mixnet_config']
        mixnet = election.get_mixnet()

        awaited = _2048_SYSTEM.parameters()
        try:
            assert cryptosys.parameters() == awaited
            messages.append('[+] cryptosys: ok')
        except AssertionError:
            err = 'Wrong cryptosystem'
            raise AssertionError(f'[-] {err}\n')

        awaited = _2048_SYSTEM.parameters()
        try:
            assert crypto_params == awaited
            messages.append('[+] crypto_params: ok')
        except AssertionError:
            err = f'Crypto params were not: {awaited}'
            raise AssertionError(f'[-] {err}\n')

        awaited = {
            'cryptosys': cryptosys,
            'nr_rounds': mixnet_config['nr_rounds'],
            'nr_mixes': mixnet_config['nr_mixes'],}
        try:
            assert mixnet.get_config() == awaited
            messages.append('[+] mixnet: ok')
        except AssertionError:
            err = "Wrong mixnet"
            raise AssertionError(f'[-] {err}\n')


if __name__ == '__main__':
    print('\n=============== Testing election stage: Uninitialized ================')
    time.sleep(.6)
    unittest.main()
