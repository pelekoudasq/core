from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import InvalidFactorError, Abortion
from .finished import Finished


class Decrypting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Finished)

    def _generate(self, *data):
        #
        # Not yet complete
        #
        election = self.get_controller()
        ciphers = election.get_mixed_ballots()
        nr_parallel = election.get_option('nr_parallel')
        for trustee in election.trustees:
            factors = election.compute_trustee_factors(trustee)
            trustee_factors = election.set_trustee_factors(trustee, factors)
            try:
                election.validate_trustee_factors(trustee_factors)
            except InvalidFactorError as err:
                raise Abortion(err)
            election.store_trustee_factors(trustee_factors)


        return ()
