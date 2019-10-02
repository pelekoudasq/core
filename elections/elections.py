from .abstracts import StageController
from .stages import Uninitialized


class GenericAPI(object):

    def set_option(self, kwarg):
        self.options.update(kwarg)

    def get_option(self, key):
        try:
            value = self.options[key]
        except KeyError:
            value = None
        return value

    def get_cryptosys(self):
        return self.cryptosys

    def get_mixnet(self):
        return self.mixnet

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def get_trustees(self):
        return self.trustees

    def get_election_key(self):
        return self.election_key

    def get_candidates(self):
        return self.candidates

    def get_voters(self):
        return self.voters

    def get_audit_codes(self):
        return self.audit_codes

    def get_voter_codes(self, voter_key):
        return self.audit_codes.get(voter_key)

    def get_cast_vote_index(self):
        return self.cast_vote_index

    def get_votes(self):
        return self.votes

    def get_cast_votes(self):
        return self.cast_votes

    def get_audit_requests(self):
        return self.audit_requests

    def get_audit_publications(self):
        return self.audit_publications

    def get_excluded_voters(self):
        return self.excluded_voters


class UninitializedAPI(object):

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet


class CreatingAPI(object):

    def set_zeus_keypair(self, zeus_keypair):
        system = self.get_cryptosys()
        private_key, public_key = system.extract_keypair(zeus_keypair)
        self.zeus_private_key = private_key
        self.zeus_public_key = public_key
        self.zeus_keypair = zeus_keypair

    def set_trustees(self, trustees):
        self.trustees = trustees

    def set_election_key(self, election_key):
        cryptosys = self.get_cryptosys()
        self.election_key = cryptosys.get_value(election_key)

    def set_candidates(self, candidates):
        self.candidates = candidates

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes


class VotingAPI(object):
    def set_cast_vote_index(self, cast_vote_index):
        self.cast_vote_index = cast_vote_index

    def set_votes(self, votes):
        self.votes = votes

    def set_cast_votes(self, cast_votes):
        self.cast_votes = cast_votes

    def set_audit_requests(self, audit_requests):
        self.audit_requests = audit_requests

    def set_audit_publications(self, audit_publications):
        self.audit_publications = audit_publications

    def set_excluded_voters(self, excluded_voters):
        self.excluded_voters = excluded_voters


class MixingAPI(object): pass
class DecryptingAPI(object): pass
class FinalizedAPI(object): pass
class AbortedAPI(object): pass


backend_apis = (GenericAPI, UninitializedAPI,
                            CreatingAPI,
                            VotingAPI,
                            MixingAPI,
                            DecryptingAPI,
                            FinalizedAPI, AbortedAPI)

class ZeusCoreElection(StageController, *backend_apis):

    def __init__(self, config, **kwargs):
        self.options = kwargs

        # Exported at stage Uninitialized
        self.cryptosys = None
        self.mixnet = None

        # Exported at stage Creating
        self.zeus_keypair = None
        self.zeus_private_key = None
        self.zeus_public_key = None
        self.trustees = None
        self.election_key = None
        self.candidates = None
        self.voters = None
        self.audit_codes = None

        # Exported at stage Voting
        self.cast_vote_index = None
        self.votes = None
        self.cast_votes = None
        self.audit_requests = None
        self.audit_publications = None
        self.excluded_voters = None

        super().__init__(Uninitialized, config)
