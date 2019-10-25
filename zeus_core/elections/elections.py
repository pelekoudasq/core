from abc import ABCMeta, abstractmethod

from .abstracts import StageController
from .stages import Uninitialized
from .validations import Validator
from .signatures import Signer, Verifier


class GenericAPI(object):

    def set_option(self, kwarg):
        self.options.update(kwarg)

    def get_option(self, key):
        """
        Returns None if the option doesn't exist
        """
        return self.options.get(key)

    def get_cryptosys(self):
        return self.cryptosys

    def get_crypto_params(self):
        return self.crypto_params

    def get_mixnet(self):
        return self.mixnet

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def get_hex_zeus_public_key(self):
        return self.hex_zeus_public_key

    def get_trustees(self):
        return self.trustees

    def get_hex_trustee_keys(self):
        """
        Returns values of trustee public keys as a list of sorted hex strings
        """
        return self.hex_trustee_keys

    def get_election_key(self):
        return self.election_key

    def get_hex_election_key(self):
        return self.hex_election_key

    def get_candidates(self):
        return self.candidates

    def get_candidates_set(self):
        return self.candidates_set

    def get_voters(self):
        # return dict(self.voters)
        return self.voters

    def get_voter(self, voter_key):
        # voters = self.voters
        # if voter_key not in voters:
        #     return None
        # return voters[voter_key]
        return self.voters.get(voter_key)

    def get_audit_codes(self):
        # return dict(self.audit_codes)
        return self.audit_codes

    def get_voter_audit_codes(self, voter_key):
        # audit_codes = self.audit_codes
        # if voter_key not in audit_codes:
        #     return None
        # return audit_codes[voter_key]
        return self.audit_codes.get(voter_key)

    def get_audit_publications(self):
        # return list(self.audit_publications)
        return self.audit_publications

    def get_audit_requests(self):
        # return dict(self.audit_requests)
        return self.audit_requests

    def get_audit_request(self, fingerprint):
        # audit_requests = self.audit_requests
        # if fingerprint not in audit_requests:
        #     return None
        # return audit_requests[fingerprint]
        return self.audit_requests.get(fingerprint)

    def get_audit_votes(self):
        return self.audit_votes

    def get_votes(self):
        # return dict(self.votes)
        return self.votes

    def get_vote(self, fingerprint):
        return self.votes.get(fingerprint)

    # def get_vote_index(self):
    def get_cast_vote_index(self):
        # return list(self.cast_vote_index)
        return self.cast_vote_index

    # def do_get_index_vote(self, index):
    def get_cast_vote_from_index(self, index):
        """
        Retrieve a cast vote's fingerprint from its index.
        Returns None if requested index exceeds current
        length of cast vote index.
        """
        cast_vote_index = self.cast_vote_index
        if index >= len(cast_vote_index):
            return None
        return cast_vote_index[index]

    # def get_all_cast_votes(self):
    def get_cast_votes(self):
        # return dict(self.cast_votes)
        return self.cast_votes

    # def do_get_cast_votes(self, voter_key):
    def get_voter_cast_votes(self, voter_key):
        # cast_votes = self.cast_votes
        # if voter_key not in cast_votes:
        #     return None
        # return cast_votes[voter_key]
        return self.cast_votes.get(voter_key)

    def get_excluded_voters(self):
        # return dict(self.excluded_voters)
        return self.excluded_voters


class UninitializedAPI(object):

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys
        self.crypto_params = self.cryptosys.parameters()

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet


class CreatingAPI(object):

    def set_zeus_keypair(self, zeus_keypair):
        system = self.get_cryptosys()
        zeus_private_key, zeus_public_key = system.extract_keypair(zeus_keypair)
        self.zeus_private_key = zeus_private_key
        self.zeus_public_key = zeus_public_key
        self.zeus_keypair = zeus_keypair
        self.hex_zeus_public_key = zeus_public_key['value'].to_hex()

    def set_trustees(self, trustees):
        self.trustees = trustees
        self.hex_trustee_keys = list(trustee['value'].to_hex()
            for trustee in trustees)
        self.hex_trustee_keys.sort()

    def set_election_key(self, election_key):
        cryptosys = self.get_cryptosys()
        self.election_key = cryptosys.get_key_value(election_key)
        self.hex_election_key = cryptosys.get_hex_value(self.election_key)

    def set_candidates(self, candidates):
        self.candidates = candidates
        self.candidates_set = set(self.candidates)

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes


class VotingAPI(object):

    def store_audit_publication(self, fingerprint):
        self.audit_publications.append(fingerprint)

    def store_audit_request(self, fingerprint, voter_key):
        """
        Stores also the corresponding audit-vote!
        """
        self.audit_requests[fingerprint] = voter_key

    def do_index_vote(self, fingerprint):
        """
        Store a vote's fingerprint in cast vote index and return its index
        """
        cast_vote_index = self.cast_vote_index
        index = len(cast_vote_index)
        cast_vote_index.append(fingerprint)
        return index

    def store_votes(self, votes):
        for vote in votes:
            fingerprint = vote['fingerprint']
            self.votes[fingerprint] = vote

    def append_vote(self, voter_key, fingerprint):
        cast_votes = self.cast_votes
        if voter_key not in cast_votes:
            cast_votes[voter_key] = []
        cast_votes[voter_key].append(fingerprint)

    def store_audit_vote(self, vote):
        self.audit_votes['fingerprint'] = vote

    def store_excluded_voter(self, voter_key, reason):
        self.excluded_voters[voter_key] = reason


class MixingAPI(object): pass
class DecryptingAPI(object): pass
class FinishedAPI(object): pass
class AbortedAPI(object): pass


backend_apis = (GenericAPI, UninitializedAPI, CreatingAPI, VotingAPI,
    MixingAPI, DecryptingAPI, FinishedAPI, AbortedAPI,)

class ZeusCoreElection(StageController, *backend_apis, Validator, Signer, metaclass=ABCMeta):

    def __init__(self, config, **kwargs):
        self.options = kwargs

        # Modified during stage Uninitialized
        self.cryptosys = None
        self.crypto_params = {}
        self.mixnet = None

        # Modified during stage Creating
        self.zeus_keypair = None
        self.zeus_private_key = None
        self.zeus_public_key = None
        self.trustees = {}
        self.election_key = None
        self.candidates = []
        self.voters = {}
        self.audit_codes = {}

        # Modified during stage Voting
        self.audit_requests = {}
        self.audit_votes = {}
        self.audit_publications = []
        self.cast_vote_index = []
        self.votes = {}
        self.cast_votes = {}
        self.excluded_voters = {}

        super().__init__(Uninitialized, config)

    @abstractmethod
    def load_submitted_votes(self):
        """
        """
