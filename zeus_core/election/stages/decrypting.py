"""
"""

from zeus_core.election.pattern import Stage
from zeus_core.election.exceptions import InvalidFactorsError, Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def run(self):
        print(__class__.__name__)      # Remove this
        election = self.get_controller()
        mixed_ballots = election.get_mixed_ballots()

        election.generate_zeus_factors()
        election.broadcast_mixed_ballots()

        # Collect trustee factors
        for trustee in election.trustees:
            trustee_factors = election.recv_factors(trustee)
            try:
                election.validate_trustee_factors(trustee, trustee_factors)
            except InvalidFactorsError as err:
                raise Abortion(err)
            election.store_trustee_factors(trustee_factors)

        # Decrypt ballots
        all_factors = election.get_all_factors()
        results = election.decrypt_ballots(mixed_ballots, all_factors)
        election.store_results(results)
