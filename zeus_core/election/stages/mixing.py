"""
"""

from zeus_core.election.pattern import Stage
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()
        mixnet = election.get_mixnet()

        votes_for_mixing, _ = election.load_votes_for_mixing()
        election.store_mix(votes_for_mixing)

        nr_parallel = election.get_option('nr_parallel')
        nr_mixes = election.get_option('nr_mixes') or 1
        do_get_last_mix = election.do_get_last_mix
        mix_ciphers = mixnet.mix_ciphers
        store_mix = election.store_mix
        mix_count = 0
        while mix_count < nr_mixes:
            last_mix = do_get_last_mix()
            mixed_ciphers = mix_ciphers(last_mix, nr_parallel=nr_parallel)
            store_mix(mixed_ciphers)
            mix_count += 1


    def export_updates(self):
        """
        """
        election = self.get_controller()

        updates = {}
        #
        # TODO: serialize
        #
        updates['mixes'] = election.do_get_all_mixes()[1:]
        # m = election.do_get_all_mixes()[1:][0]
        # print(list(m.keys()))
        # print(m['header'])
        # print(m['proof'])
        # print(type(m['original_ciphers'][0][0]))
        # print(type(m['original_ciphers'][0][1]))
        # print(type(m['proof']['cipher_collections'][0][0][0]))
        # print(m['mixed_ciphers'])
        # print(type(m['mixed_ciphers'][0][0]))
        # print(type(m['mixed_ciphers'][0][1]))

        return updates
