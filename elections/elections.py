from .abstracts import StageController
from .stages import Uninitialized


class GenericAPI(object):

    def set_option(self, kwarg):
        self.options.update(kwarg)

    def get_option(self, key):
        value = None
        try:
            value = self.options[key]
        except KeyError:
            pass
        return value

    def get_cryptosys(self):
        return self.cryptosys

    def get_mixnet(self):
        return self.mixnet

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

class UninitializedAPI(object):

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet

class CreatingAPI(object):

    def set_zeus_keypair(self, zeus_keypair):
        system = self.get_cryptosys()
        private_key, public_key = system._extract_keypair(zeus_keypair)
        self.zeus_private_key = private_key
        self.zeus_public_key = public_key
        self.zeus_keypair = zeus_keypair

    def set_trustees(self, trustees):
        self.trustees = trustees

    def set_election_key(self, election_key):
        self.election_key = election_key

    def set_candidates(self, candidates):
        self.candidates = candidates

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes

class VotingAPI(object): pass
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

        self.cryptosys = None
        self.mixnet = None
        self.zeus_keypair = None
        self.zeus_private_key = None
        self.zeus_public_key = None
        self.trustees = None
        self.candidates = None
        self.voters = None
        self.audit_codes = None

        super().__init__(Uninitialized, config)
