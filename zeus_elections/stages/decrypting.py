from zeus_elections.abstracts import Stage
from .finals import Finalized, Aborted

from time import sleep

class Decrypting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Finalized)

    def run(self):
        print('Decyrpting...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        try:
            next_input = election._get_next_input()
        except StopIteration:
            raise
        return Finalized(election, next_input)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass
