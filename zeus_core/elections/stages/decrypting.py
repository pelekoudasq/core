from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from .finalized import Finalized


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finalized)

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        return ()

    def _update_controller(self, *generated):
        pass
