from elections.abstracts import Stage, Abortion
from .finalized import Finalized


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finalized)

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        from time import sleep
        print('Decrypting...')
        sleep(.5)

        return ()

    def _update_controller(self, *generated):
        pass
