from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from zeus_core.mixnets.exceptions import InvalidMixError
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def _generate(self, *data):
        # nr_parallel =
        (votes_for_mixing,) = data
        mixed_ciphers = self.mix_ciphers(votes_for_mixing)
        last_mix = self.do_get_last_mix()
        self.validate_mix(mixed_ciphers, last_mix)
        return ()
