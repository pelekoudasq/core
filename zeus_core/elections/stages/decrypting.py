from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import InvalidFactorError, Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def _generate(self, *data):
        election = self.get_controller()
        nr_parallel = election.get_option('nr_parallel')

        mixed_ballots = election.get_mixed_ballots()

        for trustee in election.trustees:
            election.send_mixed_ballots(trustee, election.trustees[trustee])


        # Compute zeus factors
        zeus_factors = election.compute_zeus_factors(mixed_ballots)
        election.store_factors(zeus_factors)

        # Collect trustee factors
        for trustee in election.trustees:
            factors = election.collect_factors(trustee)
            try:
                # Validate attached DDH-proofs (Chaum-Pedersen)
                election.validate_trustee_factors(mixed_ballots, trustee, factors)
            except InvalidFactorError as err:
                raise Abortion(err)
            election.store_factors(factors)

        # Decrypt ballots
        all_factors = election.get_all_factors()
        plaintexts = election.decrypt_ballots(mixed_ballots, all_factors)

        # print(plaintexts)
        return (plaintexts,)
