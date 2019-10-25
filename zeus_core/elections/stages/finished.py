from zeus_core.elections.abstracts import FinalStage
from zeus_core.elections.exceptions import Abortion


class Finished(FinalStage):

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        return ()

    def _update_controller(self, *generated):
        pass
