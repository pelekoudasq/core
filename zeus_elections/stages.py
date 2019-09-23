from .abstracts import Stage, FinalStage

from time import sleep

from crypto import make_crypto
from mixnets import make_mixnet

class Uninitialized(Stage):

    def __init__(self, election, config):
        self._set(*self._extract(config))
        super().__init__(election)

    def run(self):
        election = self.controller
        cryptosys, mixnet = self.make()
        election.set_cryptosys(cryptosys)
        election.set_mixnet(mixnet)

    def next(self, input):
        return Creating(self.controller)

    def make(self):
        cryptosys = make_crypto(self.crypto_cls, self.crypto_config)
        self.mixnet_config.update({'cryptosystem': cryptosys})
        mixnet = make_mixnet(self.mixnet_cls, self.mixnet_config)
        return cryptosys, mixnet

    def _extract(self, config):
        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']

        return (crypto_cls, crypto_config, mixnet_cls, mixnet_config)

    def _set(self, crypto_cls, crypto_config, mixnet_cls, mixnet_config):
        self.crypto_cls = crypto_cls
        self.crypto_config = crypto_config
        self.mixnet_cls = mixnet_cls
        self.mixnet_config = mixnet_config

class Creating(Stage):

    def __init__(self, election):
        super().__init__(election)

    def run(self):
        election = self.controller
        zeus_keypair, trustees, candidates, voters, audit_codes = self.make()
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_candidates(candidates)
        election.set_voters(voters)
        election.set_audit_codes(audit_codes)

    def next(self, input):
        return Voting(controller=self.controller)

    def make(self):
        zeus_keypair = None
        trustees = None
        candidates = None
        voters = None
        audit_codes = None

        election = self.controller
        cryptosys = election.get_cryptosys()
        return zeus_keypair, trustees, candidates, voters, audit_codes


class Voting(Stage):
    def run(self):
        election = self.controller

        election.cast_vote_index = []
        election.votes = {}
        election.cast_votes = {}
        election.audit_requests = {}
        election.audit_publications = []
        election.excluded_voters = {}

        # print('Voting...')
        # sleep(.5)
    def next(self, input):
        return Mixing(controller=self.controller)

class Mixing(Stage):
    def run(self):
        election = self.controller

        election.mixes = []
        # print('Mixing...')
        # sleep(.5)
    def next(self, input):
        return Decrypting(controller=self.controller)

class Decrypting(Stage):
    def run(self):
        election = self.controller

        self.trustee_factors = {}
        self.zeus_decryption_factos = {}

        # print('Decyrpting...')
        # sleep(.5)
    def next(self, input):
        return Finalized(controller=self.controller)

class Finalized(FinalStage):
    def run(self):
        self.results = None

        # print('Finalized')
        # sleep(.5)

class Broken(FinalStage):
    def run(self):
        pass
        # print('BROKEN')
        # sleep(.5)
