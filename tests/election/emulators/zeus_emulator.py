"""
"""

from math import ceil
from copy import deepcopy

from zeus_core.election import ZeusCoreElection
from .client_emulators import TrusteeEmulator, VoterEmulator


class ZeusTestElection(ZeusCoreElection):
    """
    Provides a most minimal implementation of the ZeusCoreElection
    abstract class for testing purposes
    """

    def __init__(self, config, **options):
        """
        """
        super().__init__(config, **options)

        # trustees_file = config['trustees_file']
        self.trustee_clients = self.mk_trustee_clients()
        self.voter_clients = [] #self.mk_voter_clients()
        # print(self.mk_voter_clients())
        # print(self.mk_trustee_clients())


    @staticmethod
    def mk_trustee_clients():
        """
        """
        return []


    @staticmethod
    def mk_voter_clients():
        """
        """
        return []


    # ZeusCoreElection implementation

    def collect_votes(self):
        """
        Emulates collection of votes from poll
        """
        self.mk_voter_clients()
        votes, audit_requests, audit_votes = self.mk_votes_from_voters()
        votes_in_poll = iter(audit_requests + votes + audit_votes)
        while 1:
            try:
                vote = next(votes_in_poll)
            except StopIteration:
                break
            yield vote


    def send_mixed_ballots(self, trustee):
        """
        Emulates dispatch of mixed-ballots to trustee
        (triggers the trustee-client to receive them)
        """
        trustee_client = self.mk_trustee_client(trustee)
        mixed_ballots = self.get_mixed_ballots()
        trustee_client.recv_mixed_ballots(mixed_ballots)


    def recv_factors(self, trustee):
        """
        Emulates reception of factors from trustee
        (triggers the trustee-client to send them)
        """
        trustee_client = self.get_trustee_client(trustee)
        election_server = self
        trustee_factors = trustee_client.send_trustee_factors(election_server)
        trustee_factors = self.deserialize_factor_collection(trustee_factors)
        return trustee_factors


    # Makers

    def mk_trustee_client(self, public_key):
        """
        """
        crypto_config = self.get_crypto_config()
        trustee_client = TrusteeEmulator.get_from_public(crypto_config, public_key)
        self.store_trustee_client(trustee_client)
        return trustee_client


    def store_trustee_client(self, trustee_client):
        """
        """
        self.trustee_clients.append(trustee_client)


    def get_trustee_client(self, trustee):
        """
        """
        trustee_clients = self.trustee_clients
        trustee_client = (client for client in trustee_clients if \
                        trustee.value == client.get_public_key()).__next__()
        return trustee_client


    def mk_voter_client(self, voter_key):
        """
        """
        election_params = {}
        election_params['crypto_config'] = self.get_crypto_config()
        election_params['election_key'] = self.get_election_key()
        election_params['candidates'] = self.get_candidates()

        voter_params = {}
        voter_params['voter_key'] = voter_key
        voter_params['audit_codes'] = self.get_voter_audit_codes(voter_key)

        voter_client = VoterEmulator(election_params, voter_params)
        self.store_voter_client(voter_client)


    def store_voter_client(self, voter_client):
        """
        """
        self.voter_clients.append(voter_client)


    def mk_voter_clients(self):
        """
        Emulates the electoral body (one voter for each stored voter key)
        """
        voter_keys = self.get_voters()
        mk_voter_client = self.mk_voter_client
        for key in voter_keys:
            mk_voter_client(key)


    def get_voter_clients(self):
        """
        """
        return self.voter_clients


    def mk_votes_from_voters(self):
        """
        Emulates votes submitted by the totality of the electoral body:
        about half of them will be genuine votes, the rest half will be
        audit-requests (accompanied by corresponding audit publications)
        """
        voters = self.get_voter_clients()

        votes = []
        audit_requests = []
        audit_votes = []
        nr_voters = len(voters)
        for count, voter in enumerate(voters):
            voter_key = voter.voter_key
            audit_codes = voter.audit_codes
            if count < ceil(nr_voters / 2):
                vote = voter.mk_genuine_vote()
                votes.append(vote)
            else:
                audit_vote = voter.mk_audit_vote()
                audit_votes.append(audit_vote)
                audit_request = deepcopy(audit_vote)
                del audit_request['voter_secret']
                audit_requests.append(audit_request)
        return votes, audit_requests, audit_votes


    # Partial election running

    def run_until_uninitialized_stage(self):
        uninitialized = self.get_current_stage()
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
