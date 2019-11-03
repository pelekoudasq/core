from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from zeus_core.mixnets.exceptions import InvalidMixError
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def _generate(self, *data):
        (votes_for_mixing,) = data
        election = self.get_controller()
        election.store_mix(votes_for_mixing)

        mixnet = election.get_mixnet()
        nr_mixes = election.get_option('nr_mixes') or 1
        nr_parallel = election.get_option('nr_parallel')
        mix_count = 0
        while mix_count < nr_mixes:
            last_mix = election.do_get_last_mix()
            mixed_ciphers = mixnet.mix_ciphers(last_mix, nr_parallel=nr_parallel)
            mixnet.validate_mix(mixed_ciphers, last_mix, nr_parallel=nr_parallel)
            election.store_mix(mixed_ciphers)
            mix_count += 1
        return ()
