"""
"""

from zeus_core.election.pattern import Stage
from zeus_core.election.exceptions import InvalidFactorError, Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def run(self):
        print(__class__.__name__)       # Remove this
        election = self.get_controller()
        mixed_ballots = election.get_mixed_ballots()

        election.generate_zeus_factors(mixed_ballots)
        election.broadcast_mixed_ballots(mixed_ballots)

        factor_collections = election.collect_trustee_factors()

        # Validate and store trustee factors
        validate_trustee_factors = election.validate_trustee_factors
        store_trustee_factors = election.store_trustee_factors
        for trustee_factors in factor_collections:
            try:
                validate_trustee_factors(trustee_factors)
            except InvalidFactorError as err:
                raise Abortion(err)
            store_trustee_factors(trustee_factors)

        # Decrypt ballots
        all_factors = election.get_all_factors()
        results = election.decrypt_ballots(mixed_ballots, all_factors)
        election.store_results(results)


    def export_updates(self):
        """
        """
        election = self.get_controller()

        updates = {}

        all_factors = election.get_all_factors_serialized()
        updates['decryption_factors'] = all_factors

        return updates
