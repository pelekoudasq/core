from gmpy2 import mpz

from crypto.exceptions import InvalidKeyError

from elections.abstracts import Stage, Abortion
from .voting import Voting


class Creating(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Voting)

    def _extract_data(self, config):
        try:
            zeus_private_key = config['zeus_private_key']
        except KeyError:
            zeus_private_key = None
        trustees = config['trustees']
        candidates = config['candidates']
        voters = config['voters']

        return zeus_private_key, trustees, candidates, voters

    def _generate(self, zeus_private_key, trustees, candidates, voters):
        from time import sleep
        print('Creating...')
        sleep(.5)

        # Zeus keypair creation
        try:
            zeus_keypair = self.create_zeus_keypair(zeus_private_key)
        except InvalidKeyError as exc:
            raise Abortion(exc)

        # Trustees validation
        trustees = self.create_trustees(trustees)
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
        validate_public_key = cryptosys.validate_public_key
        for trustee in trustees:
            if not validate_public_key(trustee):
                raise Abortion('Invalid trustee detected: %x' % trustee['value'].value)

        # Election key computation
        election_key = self.compute_election_key(trustees, zeus_keypair)
        candidates = candidates
        voters = voters

        # Candidates validation
        nr_candidates = len(candidates)
        if nr_candidates < 1:
            raise Abortion('Insufficient number of candidates')
        output = []
        for candidate in candidates:
            if candidate in output:
                raise Abortion('Duplicate candidate detected')
            if '%' in candidate:
                raise Abortion("Candidate name cannot contain character '%'")
            if '\n' in candidate:
                raise Abortion("Candidate name cannot contain character '\\n'")
            output.append(candidate)
        canidates = output

        # Voters validation
        if not voters:
            raise Abortion('No voters provided')

        return zeus_keypair, trustees, election_key, candidates, voters

    def _update_controller(self, zeus_keypair, trustees, election_key, candidates, voters):
        election = self._get_controller()
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_election_key(election_key)
        election.set_candidates(candidates)
        election.set_voters(voters)

    # ------

    def create_zeus_keypair(self, zeus_private_key):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        zeus_keypair = cryptosys.keygen(zeus_private_key)
        return zeus_keypair

    def create_trustees(self, trustees):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        output = []
        for _trustee in trustees:
            modulus = cryptosys.parameters()['modulus']
            trustee = {
                'value': cryptosys.GroupElement(mpz(_trustee['value']), modulus),
                'proof': {
                    'commitment': cryptosys.GroupElement(mpz(_trustee['proof']['commitment']), modulus),
                    'challenge': mpz(_trustee['proof']['challenge']),
                    'response': mpz(_trustee['proof']['response'])
                }
            }
            output.append(trustee)
        return output

    def compute_election_key(self, trustees, zeus_keypair):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        public_shares = cryptosys._get_public_shares(trustees)
        zeus_public_key = cryptosys._get_public_value(zeus_keypair)
        combined = cryptosys._combine_public_keys(zeus_public_key, public_shares)
        election_key = cryptosys._set_public_key(combined)
        return election_key

    def validate_election_key(self, election_key, trustees, zeus_keypair):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        election_key = cryptosys._get_value(election_key)
        test_key = cryptosys.compute_election_key(trustees, zeus_keypair)
        return election_key == cryptosys._get_value(test_key)

    def invalidate_election_key():
        election = self._get_controller()
        election.set_election_key(None)
