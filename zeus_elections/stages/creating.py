from gmpy2 import mpz
from zeus_elections.abstracts import Stage
from .voting import Voting
from .finals import Aborted


class Creating(Stage):

    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Voting)

    def _extract_data(self, input):
        try:
            self.zeus_private_key = input['zeus_private_key']
        except KeyError:
            self.zeus_private_key = None
        self.trustees = input['trustees']
        self.candidates = input['candidates']
        self.voters = input['voters']

    def _generate(self):
        system = self.controller.get_cryptosys()
        zeus_keypair = self.create_zeus_keypair(system, self.zeus_private_key)
        trustees = self.create_trustees(system, self.trustees)
        for trustee in trustees:
            assert system.validate_public_key(trustee)
        election_key = self.compute_election_key(system, trustees, zeus_keypair)
        candidates = self.candidates
        voters = self.voters

        return zeus_keypair, trustees, election_key, candidates, voters

    def _modify_controller(self, zeus_keypair, trustees, election_key, candidates, voters):
        election = self._get_controller()
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_election_key(election_key)
        election.set_candidates(candidates)
        election.set_voters(voters)

        from time import sleep
        print('Creating...')
        sleep(.5)

    # ------

    def create_zeus_keypair(self, system, zeus_private_key):
        zeus_keypair = system.keygen(zeus_private_key)
        return zeus_keypair

    def create_trustees(self, system, trustees):
        output = []
        for _trustee in trustees:
            modulus = system.parameters()['modulus']
            trustee = {
                'value': system.GroupElement(mpz(_trustee['value']), modulus),
                'proof': {
                    'commitment': system.GroupElement(mpz(_trustee['proof']['commitment']), modulus),
                    'challenge': mpz(_trustee['proof']['challenge']),
                    'response': mpz(_trustee['proof']['response'])
                }
            }
            output.append(trustee)
        return output

    def compute_election_key(self, system, trustees, zeus_keypair):
        public_shares = system._get_public_shares(trustees)
        zeus_public_key = system._get_public_value(zeus_keypair)
        combined = system._combine_public_keys(zeus_public_key, public_shares)
        election_key = system._set_public_key(combined)
        return election_key

    def validate_election_key(self, system, election_key, trustees, zeus_keypair):
        election_key = system._get_value(election_key)
        test_key = system.compute_election_key(trustees, zeus_keypair)
        return election_key == system._get_value(test_key)
