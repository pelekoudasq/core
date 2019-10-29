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

    def _generate(self, zeus_private_key, trustees, candidates, voters):
        zeus_keypair = self.create_zeus_keypair(zeus_private_key)
        trustees = self.validate_trustees(trustees)
        election_key = self.compute_election_key(trustees, zeus_keypair)
        candidates = self.create_candidates(candidates)
        voters, audit_codes = self.create_voters_and_audit_codes(voters)

        return zeus_keypair, trustees, election_key, candidates, voters, audit_codes

    # ------

    def create_zeus_keypair(self, zeus_private_key):
        try:
            zeus_keypair = self.keygen(zeus_private_key)
        except InvalidKeyError as err:
            raise Abortion(err)
        return zeus_keypair

    def validate_trustees(self, trustees):
        trustees = self.deserialize_trustees(trustees)
        validate_public_key = self.validate_public_key
        new_trustees = dict()
        for trustee in trustees:
            if not validate_public_key(trustee):
                err = 'Invalid trustee detected: %x' % trustee['value'].value
                raise Abortion(err)
            public_key = trustee['value']
            proof = trustee['proof']
            new_trustees[public_key] = proof
        return new_trustees

    def compute_election_key(self, trustees, zeus_keypair):
        public_shares = self.get_public_shares(trustees)
        zeus_public_key = self._get_public_value(zeus_keypair)
        combined = self._combine_public_keys(zeus_public_key, public_shares)
        election_key = self._set_public_key(combined)
        return election_key

    def get_public_shares(self, trustees):
        get_key_value = self.get_key_value
        public_shares = [get_key_value(public_key)
            for public_key in trustees.keys()]
        return public_shares

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
