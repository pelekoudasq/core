from zeus_elections.abstracts import Stage
from .mixing import Mixing
from .finals import Aborted


class Voting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Mixing)

    def _extract_data(self, config):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Voting')
        sleep(.5)
