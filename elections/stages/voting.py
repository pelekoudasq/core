from elections.abstracts import Stage
from .mixing import Mixing
from .finals import Aborted


class Voting(Stage):

    def _extract_data(self):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Voting...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        return Mixing(controller=election)
