from zeus_elections.abstracts import Stage
from .finals import Finalized, Aborted


class Decrypting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Finalized)

    def _extract_data(self, config):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Decrypting')
        sleep(.5)
