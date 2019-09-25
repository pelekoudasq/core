from elections.abstracts import Stage
from .finals import Finalized, Aborted


class Decrypting(Stage):

    def _extract_data(self):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Decrypting...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        return Finalized(controller=election)
