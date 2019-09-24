from zeus_elections.abstracts import Stage
from .decrypting import Decrypting
from .finals import Aborted


class Mixing(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Decrypting)

    def _extract_data(self, config):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Mixing')
        sleep(.5)
