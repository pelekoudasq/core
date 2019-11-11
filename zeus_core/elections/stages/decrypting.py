from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import InvalidFactorError, Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def _generate(self, *data):
        election = self.get_controller()

        mixed_ballots = election.get_mixed_ballots()
        nr_parallel = election.get_option('nr_parallel')

        # Compute zeus factors

        zeus_factors = election.compute_zeus_factors(mixed_ballots)
        try:
            zeus_public_key = election.get_zeus_public_key()
            election.validate_trustee_factors(mixed_ballots, zeus_public_key, zeus_factors)
        except InvalidFactorError as err:
            raise Abortion(err)
        election.store_factors(zeus_factors)

        # Compute trustee factors for all trustees

        for trustee in election.trustees:
            trustee_keypair = election.get_trustee_keypair(trustee)
            # TODO: Transfer this to trustee's side
            factors = election.compute_trustee_factors(mixed_ballots, trustee_keypair)
            try:
                election.validate_trustee_factors(mixed_ballots, trustee, factors)
            except InvalidFactorError as err:
                raise Abortion(err)
            election.store_factors(factors)

        # Decrypt ballots

        all_factors = election.get_all_factors()
        plaintexts = election.decrypt_ballots(mixed_ballots, all_factors)

        # print(plaintexts)
        return (plaintexts,)
