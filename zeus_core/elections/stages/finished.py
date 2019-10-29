from zeus_core.elections.abstracts import FinalStage
from zeus_core.elections.exceptions import Abortion


class Finished(FinalStage):
    def _generate(self, *data):
        return ()
