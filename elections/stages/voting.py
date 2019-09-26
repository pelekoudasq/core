from elections.abstracts import Stage, Abortion
from .mixing import Mixing


class Voting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Mixing)

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        from time import sleep
        print('Voting...')
        sleep(.5)

        return ()

    def _update_controller(self, *generated):
        pass
