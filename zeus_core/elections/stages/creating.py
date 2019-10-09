from gmpy2 import mpz

from zeus_core.crypto.exceptions import InvalidKeyError
from zeus_core.utils import random_integer

from zeus_core.elections.abstracts import Stage
from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.constants import VOTER_KEY_CEIL, VOTER_SLOT_CEIL
from .voting import Voting


class Creating(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Voting)

    def _extract_data(self, config):
        try:
            zeus_private_key = config['zeus_private_key']
        except KeyError:
            zeus_private_key = None
        try:
            trustees = config['trustees']
            candidates = config['candidates']
            voters = config['voters']
        except KeyError as err:
            raise Abortion(err)

        return zeus_private_key, trustees, candidates, voters

    def _generate(self, zeus_private_key, trustees, candidates, voters):
        zeus_keypair = self.create_zeus_keypair(zeus_private_key)
        trustees = self.validate_trustees(trustees)
        election_key = self.compute_election_key(trustees, zeus_keypair)
        candidates = self.create_candidates(candidates)
        voters, audit_codes = self.create_voters_and_audit_codes(voters)

        return zeus_keypair, trustees, election_key, candidates, voters, audit_codes

    def _update_controller(self, zeus_keypair, trustees, election_key,
            candidates, voters, audit_codes):
        election = self._get_controller()
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_election_key(election_key)
        election.set_candidates(candidates)
        election.set_voters(voters)
        election.set_audit_codes(audit_codes)

    # ------

    def create_zeus_keypair(self, zeus_private_key):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
        try:
            zeus_keypair = cryptosys.keygen(zeus_private_key)
        except InvalidKeyError as err:
            raise Abortion(err)
        return zeus_keypair

    def compute_election_key(self, trustees, zeus_keypair):
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        public_shares = cryptosys.get_public_shares(trustees)
        zeus_public_key = cryptosys._get_public_value(zeus_keypair)
        combined = cryptosys._combine_public_keys(zeus_public_key, public_shares)
        election_key = cryptosys._set_public_key(combined)
        return election_key

    def validate_trustees(self, trustees):
        trustees = self.deserialize_trustees(trustees)
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
        validate_public_key = cryptosys.validate_public_key
        for trustee in trustees:
            if not validate_public_key(trustee):
                err = 'Invalid trustee detected: %x' % trustee['value'].value
                raise Abortion(err)
        return trustees

    def create_candidates(self, candidates):
        if not candidates:
            err = 'Zero number of candidates provided'
            raise Abortion(err)
        new_candidates = []
        append = new_candidates.append
        for candidate in candidates:
            if candidate in new_candidates:
                err = 'Duplicate candidate detected'
                raise Abortion(err)
            if '%' in candidate:
                err = "Candidate name cannot contain character '%'"
                raise Abortion(err)
            if '\n' in candidate:
                err = "Candidate name cannot contain character '\\n'"
                raise Abortion(err)
            append(candidate)
        canidates = new_candidates
        return candidates

    def create_voters_and_audit_codes(self, voters,
            voter_slot_ceil=VOTER_SLOT_CEIL):
        if not voters:
            err = 'Zero number of voters provided'
            raise Abortion(err)
        nr_voter_names = len(set(_[0] for _ in voters))
        if nr_voter_names != len(voters):
            err = 'Duplicate voter names'
            raise Abortion(err)
        new_voters = {}
        audit_codes = {}
        random_hex = lambda ceil: '%x' % random_integer(2, ceil)
        for name, weight in voters:
            voter_key = random_hex(VOTER_KEY_CEIL)
            while voter_key in new_voters:
                # ~ Avoid duplicate voter keys
                # ~ Note for dev: this may lead to infinite loop for small
                # ~ values of VOTER_KEY_CEIL! (not the case in production)
                voter_key = random_hex(VOTER_KEY_CEIL)
            voter_audit_codes = list(random_hex(voter_slot_ceil) for _ in range(3))
            new_voters[voter_key] = (name, weight)
            audit_codes[voter_key] = voter_audit_codes
        audit_code_set = set(tuple(values) for values in audit_codes.values())
        if len(audit_code_set) < 0.5 * len(new_voters):
            err = 'Insufficient slot variation attained'
            raise Abortion(err)
        voters = new_voters

        return voters, audit_codes

    def deserialize_trustees(self, trustees):
        """
        """
        cryptosys = self._get_controller().get_cryptosys()
        deserialize_public_key = cryptosys.deserialize_public_key
        deserialized = []
        for trustee in trustees:
            trustee = deserialize_public_key(trustee['value'], trustee['proof'])
            deserialized.append(trustee)
        return deserialized


    # def validate_election_key(self, election_key, trustees, zeus_keypair):
    #     election = self._get_controller()
    #     cryptosys = election.get_cryptosys()
    #
    #     election_key = cryptosys.get_value(election_key)
    #     test_key = cryptosys.compute_election_key(trustees, zeus_keypair)
    #     return election_key == cryptosys.get_value(test_key)
    #
    # def invalidate_election_key():
    #     election = self._get_controller()
    #     election.set_election_key(None)
