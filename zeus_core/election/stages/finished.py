"""
"""

from zeus_core.election.pattern import FinalStage
from zeus_core.election.exceptions import Abortion


class Finished(FinalStage):


    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()

        results = election.get_results()
        election._update_exports({'results': results})
