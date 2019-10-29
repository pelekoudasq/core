from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from .decrypting import Decrypting


class Mixing(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Decrypting)

    def _generate(self, *data):
        return ()
