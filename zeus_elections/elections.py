from .abstracts import StageController
from .stages import Uninitialized

class ZeusCoreElection(object):

    def __init__(self):
        from zeus_elections.stages import Uninitialized
        self.stageController = StageController(initial_cls=Uninitialized)

    def run(self):
        self.stageController.run_all([0, 0, 0, 0, 0, 0])
