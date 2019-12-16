"""
"""

from zeus_core.election.pattern import FinalStage
from zeus_core.election.exceptions import Abortion


class Finished(FinalStage):

    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()

        results = election.get_results()
        election._update({'results': results})
        fingerprint = election.generate_fingerprint()
        election._update({'election_fingerprint': fingerprint})


    def export_updates(self):
        """
        """
        election = self.get_controller()

        updates = dict()
        updates['election_report'] = election.generate_report()

        # print(election.exports)                           # Remove this
        print('\n' + updates['election_report'])          # Remove this
        return updates
