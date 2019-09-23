from .abstracts import StageController
from .stages import Uninitialized

class ZeusCoreElection(StageController):

    def __init__(self, config, **kwargs):
        initial_stage = Uninitialized(self, config)
        super().__init__(initial_stage, Uninitialized)

    def run(self):
        self.run_all([0, 0, 0, 0, 0])

    # Uninitialized API

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet

    def get_cryptosys(self):
        return self.cryptosys

    def get_mixnet(self):
        return self.mixnet

    # Creating API

    def set_zeus_keypair(self, zeus_keypair):
        self.zeus_keypair = zeus_keypair

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def get_zeus_key_proof(self):
        return self.zeus_key_proof

    def set_trustees(self, trustees):
        self.trustees = trustees

    def set_candidates(self, candidates):
        self.candidates = candidates

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes

    # Voting API
