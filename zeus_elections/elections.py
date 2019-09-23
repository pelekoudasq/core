from .abstracts import StageController
from .stages import Uninitialized

class ZeusCoreElection(StageController):

    def __init__(self, config):
        initial_stage = Uninitialized(self, config)
        super().__init__(initial_stage, Uninitialized)

    def run(self):
        self.run_all([0, 0, 0, 0, 0, 0])
