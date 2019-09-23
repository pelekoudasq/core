from .abstracts import StageController
from .stages import Uninitialized

class ZeusCoreElection(StageController):

    def __init__(self, config, **kwargs):
        inputs = self._extract_inputs(config)
        super().__init__(Uninitialized, iter(inputs))

    def _extract_inputs(self, config):
        inputs = 6 * [None]

        # Make input for stage Uninitialized
        inputs[0] = {}
        inputs[0].update({'crypto': config['crypto']})
        inputs[0].update({'mixnet': config['mixnet']})

        # Make input for stage Creating
        inputs[1] = {}
        inputs[1].update({'zeus_private_key': config['zeus_private_key']})
        # Make input for stage Voting
        inputs[2] = {}
        # Make input for stage Mixing
        inputs[3] = {}
        # Make input for stage Decrypting
        inputs[4] = {}
        # Make input for stage Finalized
        inputs[5] = {}

        return inputs

    # Uninitialized stage API

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet

    def get_cryptosys(self):
        return self.cryptosys

    def get_mixnet(self):
        return self.mixnet

    # Creating stage API

    def set_zeus_keypair(self, zeus_keypair):
        system = self.get_cryptosys()
        private_key, public_key = system._extract_keypair(zeus_keypair)
        self.zeus_private_key = private_key
        self.zeus_public_key = public_key
        self.zeus_keypair = zeus_keypair

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def set_trustees(self, trustees):
        self.trustees = trustees

    def set_candidates(self, candidates):
        self.candidates = candidates

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes

    # Voting stage API
    # Mixing stage API
    # Decrypting stage API
    # Finalized stage API
