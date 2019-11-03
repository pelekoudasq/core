from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def _generate(self, *data):
        election = self.get_controller()
        ciphers = election.get_mixed_ballots()

        nr_parallel = election.get_option('nr_parallel')
        #
        #
        # Not yet implemented
        #
        #
        return ()
