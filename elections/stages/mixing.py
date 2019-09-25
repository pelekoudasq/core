from elections.abstracts import Stage
from .decrypting import Decrypting
from .finals import Aborted


class Mixing(Stage):

    def _extract_data(self):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Mixing...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        return Decrypting(controller=election)
