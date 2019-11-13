import json
from math import ceil
from copy import deepcopy
from zeus_core.elections import ZeusCoreElection
from zeus_core.elections.stages import Uninitialized
from tests.elections.config_samples import config_1
from tests.elections.clients import Trustee
from tests.elections.utils import mk_voters, mk_votes_from_voters

class ZeusTestElection(ZeusCoreElection):
    """
    Provides a most minimal concrete implementation of the
    ZeusCoreElection abstract class for testing purposes
    """
    def __init__(self, config, **options):
        """
        """
        super().__init__(config, **options)
        self.real_trustees = []

    def collect_votes(self):
        """
        """
        voters = mk_voters(self)
        votes, audit_requests, audit_votes = mk_votes_from_voters(voters)
        submitted_votes = iter(audit_requests + votes + audit_votes)
        while 1:
            try:
                vote = next(submitted_votes)
            except StopIteration:
                break
            yield vote

    def send_mixed_ballots(self, trustee, proof):
        """
        Will also trigger the trustee to compute
        their factors for testing purposes
        """
        mixed_ballots = self.get_mixed_ballots()

        crypto = {}
        crypto['cls'] = self.config['crypto_cls']
        crypto['config'] = self.config['crypto_config']

        trustee = Trustee.get_from_public(crypto, trustee, proof)
        self.real_trustees.append(trustee)
        trustee.compute_trustee_factors(mixed_ballots)

    def collect_factors(self, trustee):
        """
        """
        real_trustee = (real_trustee for real_trustee in self.real_trustees
            if trustee.value == real_trustee.keypair['public']['value']).__next__()
        trustee_factors = real_trustee.get_factors()
        return trustee_factors
        # with open('tests/elections/trustee-publics.json') as f:
        #     trustee_publics = json.load(f)
        # with open('tests/elections/trustee-privates.json') as f:
        #     trustee_privates = json.load(f)
        #
        # trustee_index = [i for i in range(len(trustee_publics)) if trustee.value == trustee_publics[i]['value']][0]
        #
        # cryptosys = self.get_cryptosys()
        #
        # proof = self.trustees[trustee]
        # private_key = cryptosys.int_to_exponent(trustee_privates[trustee_index])
        #
        # keypair = {
        #     'private': private_key,
        #     'public': {
        #         'value': trustee,
        #         'proof': proof
        #     }
        # }
        #
        # trustee_factors = self.compute_trustee_factors(self.get_mixed_ballots(), keypair)
        # return trustee_factors

    # Test utils (irrelevant to implementation of ZeusCoreElection abstract class)

    def run_until_uninitialized_stage(self):
        uninitialized = self._get_current_stage()
        return uninitialized

    def run_until_creating_stage(self):
        uninitialized = self.run_until_uninitialized_stage()
        uninitialized.run()
        creating = uninitialized.next()
        return creating

    def run_until_voting_stage(self):
        creating = self.run_until_creating_stage()
        creating.run()
        voting = creating.next()
        return voting

    def run_until_mixing_stage(self):
        voting = self.run_until_voting_stage()
        voting.run()
        mixing = voting.next()
        return mixing

    def run_until_decrypting_stage(self):
        mixing = self.run_until_mixing_stage()
        mixing.run()
        decrypting = mixing.next()
        return decrypting

    def run_until_finished_stage(self):
        decrypting = self.run_until_decrypting_stage()
        decrypting.run()
        finished = decrypting.next()
        return finished
