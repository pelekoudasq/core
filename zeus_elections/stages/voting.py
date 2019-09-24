from zeus_elections.abstracts import Stage
from .mixing import Mixing
from .finals import Aborted

from time import sleep

class Voting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Mixing)

    def run(self):
        print('Voting...')
        sleep(.5)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass
