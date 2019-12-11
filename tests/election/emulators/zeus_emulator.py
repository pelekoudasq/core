"""
"""

from math import ceil
import json
from copy import deepcopy

from zeus_core.election import ZeusCoreElection
from .clients import TrusteeEmulator, VoterEmulator


class ZeusTestElection(ZeusCoreElection):
    """
    A minimal implementation of the ZeusCoreElection
    abstract class for demo and testing purposes
    """

    def __init__(self, config, **options):
        """
        """
        crypto = config['crypto']
        voters = config['voters']
        trustees = config['trustees']

        super().__init__(config, **options)

        self.trustee_clients = self.mk_trustee_clients(crypto, trustees)
        self.voter_clients = self.mk_voter_clients(crypto, voters)


    @staticmethod
    def mk_trustee_clients(crypto_config, trustees_file):
        """
        """
        trustee_clients = []
        with open(trustees_file) as __file:
            trustees = json.load(__file)
        for trustee in trustees:
            client = TrusteeEmulator(public=trustee['value'])
            trustee_clients.append(client)
        return trustee_clients


    @staticmethod
    def mk_voter_clients(crypto_config, voters_file):
        """
        """
        voter_clients = []
        with open(voters_file) as __file:
            voters = json.load(__file)
        for name, weight in voters:
            client = VoterEmulator(name, weight)
            voter_clients.append(client)
        return voter_clients


    # ZeusCoreElection implementation

    @staticmethod
    def resolve_secret(config):
        """
        """
        resolved = None
        zeus_secret = config.get('zeus_secret', None)
        if zeus_secret:
            with open(zeus_secret) as __file:
                resolved = json.load(__file)
        return resolved


    @staticmethod
    def resolve_lists(config):
        """
        """
        resolved = []

        trustees = config['trustees']
        candidates = config['candidates']
        voters = config['voters']
        for file in (trustees, candidates, voters):
            with open(file) as __file:
                lst = json.load(__file)
            resolved.append(lst)

        return resolved


    def broadcast_election(self):
        """
        """
        #
        # ~ Send zeus crypto params to trustees so that they can
        # ~ configure their local cryptosystems appropriately
        #
        crypto_config = self.get_crypto_config()
        send_crypto = self.send_crypto
        trustees = self.get_trustees()
        for trustee in trustees:
            send_crypto(trustee, crypto_config)
        #
        # ~ Inform each voter about
        #
        # ~ (1) the election's public key
        # ~ (2) candidates
        # ~ (3) zeus crypto params (so that they can configure
        # ~     their local cryptosystems appropriately)
        # ~ (4) their assigned voter key
        # ~ (5) their assigned audit codes
        #
        get_voter_audit_codes = self.get_voter_audit_codes
        send_election_params = self.send_election_params
        election_header = self._get_election_header()
        voters = self.get_voters()
        for voter_key in voters:
            voter_params = {}
            voter_params.update(election_header)
            audit_codes = get_voter_audit_codes(voter_key)
            voter_params['voter_key'] = voter_key
            voter_params['audit_codes'] = audit_codes
            send_election_params(voter_key, voter_params)


    def collect_votes(self):
        """
        Emulates collection of votes from poll
        """
        votes, audit_requests, audit_votes = self.mk_votes_from_voters()
        votes_in_poll = iter(audit_requests + votes + audit_votes)
        while 1:
            try:
                vote = next(votes_in_poll)
            except StopIteration:
                break
            yield vote


    def broadcast_mixed_ballots(self, mixed_ballots):
        """
        Emulates broadcasting of mixed ballots to trustees
        (triggers each trustee-client to receive them)
        """
        send_mixed_ballots = self.send_mixed_ballots
        for trustee in self.get_trustees():
            send_mixed_ballots(trustee, mixed_ballots)


    def collect_trustee_factors(self):
        """
        Emulates collection of factors from trustees
        """
        factor_collections = []
        for trustee in self.trustees:
            trustee_factors = self.recv_factors(trustee)
            factor_collections.append(trustee_factors)
        return factor_collections


    # Vote generation

    def mk_votes_from_voters(self):
        """
        Emulates votes submitted by the totality of the electoral body:
        about half of them will be genuine votes, the rest half will be
        audit-requests (accompanied by corresponding audit publications)
        """
        voters = self.voter_clients
        nr_voters = len(voters)

        votes = []
        audit_requests = []
        audit_votes = []
        for count, voter in enumerate(voters):
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


    def get_voter_clients(self):
        clients = self.voter_clients
        return clients


    # Communication

    def detect_trustee_client(self, trustee):
        """
        """
        trustee_clients = self.trustee_clients
        trustee_client = (client for client in trustee_clients if \
                    trustee.value == client.public).__next__()
        return trustee_client


    def detect_voter_client(self, voter_name):
        """
        """
        voter_clients = self.voter_clients
        voter_client = (client for client in voter_clients if \
                    client.get_name() == voter_name).__next__()
        return voter_client


    def send_crypto(self, trustee, crypto_config):
        """
        Triggers the client to receive
        """
        trustee_client = self.detect_trustee_client(trustee)
        trustee_client.recv_crypto(crypto_config)


    def send_election_params(self, voter, election_params):
        """
        Triggers the client to receive
        """
        voter_name = self.get_voter_name(voter)
        voter_client = self.detect_voter_client(voter_name)
        voter_client.recv_election_params(election_params)


    def send_mixed_ballots(self, trustee, mixed_ballots):
        """
        Emulates dispatch of mixed-ballots to trustee
        (triggers the trustee-client to receive them)
        """
        trustee_client = self.detect_trustee_client(trustee)
        trustee_client.recv_mixed_ballots(mixed_ballots)


    def recv_factors(self, trustee):
        """
        Emulates reception of factors from trustee
        (triggers the trustee-client to send them)
        """
        trustee_client = self.detect_trustee_client(trustee)
        election_server = self
        trustee_factors = trustee_client.send_trustee_factors(election_server)
        trustee_factors = self.deserialize_factor_collection(trustee_factors)
        return trustee_factors


    # Partial election running

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
