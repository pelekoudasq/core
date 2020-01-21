import pytest
from copy import deepcopy
import time

from tests.election.stages.abstracts import StageTester
from tests.election.makers import mk_election

from zeus_core.election.exceptions import Abortion
from zeus_core.mixnets.exceptions import InvalidMixError, MixNotVerifiedError

import unittest

class TestMixing(StageTester, unittest.TestCase):


    @classmethod
    def run_until_stage(cls):
        election = mk_election(nr_mixes=7)
        cls.election = election
        election.run_until_mixing_stage()
        cls.stage = election._get_current_stage()

    def get_mixing_context(self):
        election, config, stage, messages = self.get_context()
        mixnet = election.get_mixnet()
        votes_for_mixing = election.load_votes_for_mixing()[0]
        election.store_mix(votes_for_mixing)
        return (election, config, stage, mixnet, votes_for_mixing, messages)


    def test_valid_mixing(self):
        (election, config, stage, mixnet,
            votes_for_mixing, messages) = self.get_mixing_context()
        messages.append('\nTesting valid mixes\n')
        nr_mixes = 5
        nr_parallel = election.get_option('nr_parallel')
        mix_count = 0
        while mix_count < nr_mixes:
            last_mix = election.do_get_last_mix()
            mixed_ciphers = mixnet.mix_ciphers(last_mix, nr_parallel=nr_parallel)
            with self.subTest():
                mixnet.validate_mix(mixed_ciphers, last_mix, nr_parallel=nr_parallel)
                messages.append('[+] Mix successfully validated')
            election.store_mix(mixed_ciphers)
            mix_count += 1


    def test_invalid_mixing(self):
        (election, config, stage, mixnet,
            votes_for_mixing, messages) = self.get_mixing_context()
        messages.append('\nTesting invalid mixes\n')

        last_mix = deepcopy(election.do_get_last_mix())
        with self.subTest(last_mix=last_mix):
            mixed_ciphers = mixnet.mix_ciphers(last_mix)
            with self.assertRaises(InvalidMixError):
                del mixed_ciphers['original_ciphers']
                mixnet.validate_mix(mixed_ciphers, last_mix)
            messages.append('[+] Invalid mix successfully detected: Malformed')

        last_mix = deepcopy(election.do_get_last_mix())
        with self.subTest(last_mix=last_mix):
            mixed_ciphers = mixnet.mix_ciphers(last_mix)
            with self.assertRaises(InvalidMixError):
                hex_parameters, _ = mixnet.extract_header(mixed_ciphers)
                corrupt = mixed_ciphers['header']['modulus']
                mixed_ciphers['header']['modulus'] = corrupt[:-1]
                mixnet.validate_mix(mixed_ciphers, last_mix)
            messages.append('[+] Invalid mix successfully detected: Cryptosystem mismatch')
        mixed_ciphers['header']['modulus'] = corrupt # Restore for later use

        last_mix = deepcopy(election.do_get_last_mix())
        with self.subTest(last_mix=last_mix):
            mixed_ciphers = mixnet.mix_ciphers(last_mix)
            with self.assertRaises(InvalidMixError):
                mixed_ciphers['original_ciphers'] = []
                mixnet.validate_mix(mixed_ciphers, last_mix)
            messages.append('[+] Invalid mix successfully detected: Not a mix of latest ciphers')

        last_mix = deepcopy(election.do_get_last_mix())
        with self.subTest(last_mix=last_mix):
            mixed_ciphers = mixnet.mix_ciphers(last_mix)
            with self.assertRaises(MixNotVerifiedError):
                mixed_ciphers['proof']['challenge'] += '0'
                mixnet.validate_mix(mixed_ciphers, last_mix)
            messages.append('[+] Invalid mix proof successfully detected: Wrong proof')


if __name__ == '__main__':
    print('\n=================== Testing election stage: Mixing ===================')
    time.sleep(.6)
    unittest.main()
