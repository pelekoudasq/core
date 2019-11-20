"""
"""

from zeus_core.election.pattern import Stage
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def run(self):
        election = self.get_controller()

        votes_for_mixing, _ = election.load_votes_for_mixing()
        election.store_mix(votes_for_mixing)

        mixnet = election.get_mixnet()
        nr_mixes = election.get_option('nr_mixes') or 1
        nr_parallel = election.get_option('nr_parallel')
        mix_count = 0
        while mix_count < nr_mixes:
            last_mix = election.do_get_last_mix()
            mixed_ciphers = mixnet.mix_ciphers(last_mix, nr_parallel=nr_parallel)
            election.store_mix(mixed_ciphers)
            mix_count += 1
