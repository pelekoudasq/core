from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from zeus_core.mixnets.exceptions import InvalidMixError
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def _generate(self, *data):
        election = self.get_controller()
        (votes_for_mixing,) = data
        election.store_mix(votes_for_mixing)
        nr_parallel = election.get_option('nr_parallel')
        mixed_ciphers = self.mix_ciphers(votes_for_mixing, nr_parallel=nr_parallel)
        last_mix = self.do_get_last_mix()
        self.validate_mix(mixed_ciphers, last_mix, nr_parallel=nr_parallel)
        return ()
