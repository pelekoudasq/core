"""
"""

from zeus_core.election.pattern import FinalStage
from zeus_core.election.exceptions import Abortion


class Finished(FinalStage):

    def run(self):
        election = self.get_controller()

        results = election.get_results()
        print('\n', results, sep='')
