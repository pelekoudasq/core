from .abstracts import StageController
from .stages import Uninitialized

class ZeusCoreElection(StageController):

    def __init__(self, config, **kwargs):
        super().__init__(Uninitialized, config)


    # Generic API

    def get_cryptosys(self):
        return self.cryptosys

    def get_mixnet(self):
        return self.mixnet

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key


    # Uninitialized API

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet


    # Creating API

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


    # Voting API
    # Mixing API
    # Decrypting API
    # Finalized API
