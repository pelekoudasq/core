from zeus_core.elections import ZeusCoreElection
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

        # ~ Will hold trustee clients. Not to be confused with the
        # ~ `trustees` attribute of ZeusCoreElection, referring to
        # ~ the trustees's public keys and accompanying proofs
        self.__trustees = []


    def collect_votes(self):
        """
        Emulates collection of votes from poll
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


    def send_mixed_ballots(self, trustee):
        """
        Emulates mixed ballots dispatch to trustee

        Creates the trustee client from the provided public key value and proof
        and triggers the trustee to compute their factors for testing purposes.
        """
        mixed_ballots = self.get_mixed_ballots()

        crypto = self.get_crypto_config()
        __trustee = Trustee.get_from_public(crypto, trustee)
        self.__trustees.append(__trustee)
        __trustee.compute_trustee_factors(mixed_ballots, store=True)


    def collect_factors(self, trustee):
        """
        Emulates trustee-factors collection
        """
        __trustee = (__trustee for __trustee in self.__trustees
            if trustee.value == __trustee.keypair['public']['value']).__next__()
        trustee_factors = __trustee.get_factors()
        return trustee_factors


    # Testing utilities (irrelevant to implementation of ZeusCoreElection abstract class)

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
