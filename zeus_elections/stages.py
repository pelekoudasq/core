from .abstracts import Stage, FinalStage

from time import sleep

class Uninitialized(Stage):
    def __init__(self, election, config):
        election.crypto = None
        election.mixnet = None

        self.config = config
        super().__init__(election)

    def run(self):
        election = self.controller

        election.crypto = None
        election.mixnet = None
        print('Uninitialized')
        sleep(.5)
    def next(self, input):
        return Creating(controller=self.controller)

class Creating(Stage):
    def run(self):
        election = self.controller

        election.crypto = None

        election.zeus_private = None
        election.zeus_public = None
        election.zeus_key_proof = None

        election.trustees = {}
        election.public_key = None

        election.candidates = []
        election.voters = {}
        election.audit_codes = {}

        print('Creating')
        sleep(.5)



    def next(self, input):
        return Voting(controller=self.controller)

class Voting(Stage):
    def run(self):
        election = self.controller

        election.cast_vote_index = []
        election.votes = {}
        election.cast_votes = {}
        election.audit_requests = {}
        election.audit_publications = []
        election.excluded_voters = {}

        print('Voting...')
        sleep(.5)
    def next(self, input):
        return Mixing(controller=self.controller)

class Mixing(Stage):
    def run(self):
        election = self.controller

        election.mixes = []
        print('Mixing...')
        sleep(.5)
    def next(self, input):
        return Decrypting(controller=self.controller)

class Decrypting(Stage):
    def run(self):
        election = self.controller

        self.trustee_factors = {}
        self.zeus_decryption_factos = {}

        print('Decyrpting...')
        sleep(.5)
    def next(self, input):
        return Finalized(controller=self.controller)

class Finalized(FinalStage):
    def run(self):
        self.results = None

        print('Finalized')
        sleep(.5)

class Broken(FinalStage):
    def run(self):
        print('BROKEN')
        sleep(.5)
