"""
"""

from abc import ABCMeta, abstractmethod
from itertools import repeat
import json

from zeus_core.crypto import mk_cryptosys
from zeus_core.mixnets import mk_mixnet
from zeus_core.crypto.exceptions import (AlgebraError, WrongCryptoError,
                                        WeakCryptoError, InvalidKeyError)
from zeus_core.mixnets.exceptions import MixnetConstructionError
from zeus_core.utils import random_integer

from .pattern import StageController
from .interfaces import (GenericAPI, KeyManager, VoteSubmitter, FactorGenerator,
                    FactorValidator, Decryptor)
from .stages import Uninitialized, Creating, Voting, Mixing, Decrypting, Finished
from .exceptions import (InvalidTrusteeError, InvalidCandidatesError,
                    InvalidVotersError, InvalidVoteError, VoteRejectionError,
                    InvalidFactorsError, Abortion)
from .constants import VOTER_KEY_CEIL, VOTER_SLOT_CEIL


class ZeusCoreElection(StageController, GenericAPI, KeyManager, VoteSubmitter,
                        FactorGenerator, FactorValidator, Decryptor,
                        metaclass=ABCMeta):
    """
    """

    def __init__(self, config, **options):
        """
        """
        self.config = self.adapt_config(config)
        self.options = options
        self.initialize()

        super().__init__(Uninitialized)


    @staticmethod
    def adapt_config(config):
        """
        """
        try:
            crypto = config['crypto']
            mixnet = config['mixnet']
            trustees_file_path = config['trustees_file']
            candidates = config['candidates']
            voters = config['voters']
        except KeyError as e:
            err = f"Incomplete election config: missing {e}"
            raise Abortion(err)
        config['zeus_private_key'] = config.get('zeus_private_key')
        with open(trustees_file_path) as trustees_file:
            config['trustees'] = json.load(trustees_file)
        return config


    def initialize(self):
        """
        """
        self.cryptosys = None
        self.mixnet    = None
        self.zeus_keypair = None
        self.zeus_private_key = None
        self.zeus_public_key  = None
        self.trustees     = dict()
        self.election_key = None
        self.candidates   = []
        self.voters       = dict()
        self.audit_codes  = dict()
        self.audit_requests     = dict()
        self.audit_publications = []
        self.audit_votes     = dict()
        self.cast_vote_index = []
        self.votes           = dict()
        self.cast_votes      = dict()
        self.excluded_voters = dict()
        self.mixes           = []
        self.zeus_factors    = None
        self.trustees_factors = dict()
        self.results = []


    @abstractmethod
    def collect_votes(self):
        """
        """

    @abstractmethod
    def send_mixed_ballots(self, trustee):
        """
        """

    @abstractmethod
    def recv_factors(self, trustee):
        """
        """


    def extract_config(self):
        """
        """
        config = self.config

        crypto_config = config.get('crypto')
        mixnet_config = config.get('mixnet')
        zeus_private_key = config.get('zeus_private_key')
        trustees = config.get('trustees')
        candidates = config.get('candidates')
        voters = config.get('voters')

        return (crypto_config, mixnet_config,
            zeus_private_key, trustees, candidates, voters)


    # Cryptosys and mixnet init

    def init_cryptosys(self):
        """
        """
        crypto_config = self.get_crypto_config()

        try:
            cryptosys = mk_cryptosys(crypto_config)
        except (AlgebraError, WeakCryptoError, WrongCryptoError):
            raise
        self.set_cryptosys(cryptosys)


    def init_mixnet(self):
        """
        """
        mixnet_config = self.get_mixnet_config()

        try:
            mixnet = mk_mixnet(mixnet_config)
        except MixnetConstructionError as err:
            raise
        self.set_mixnet(mixnet)


    # Zeus key generation

    def create_zeus_keypair(self):
        """
        """
        _, _, zeus_private_key, _, _, _ = self.extract_config()

        try:
            zeus_keypair = self.keygen(zeus_private_key)
        except InvalidKeyError:
            raise
        self.set_zeus_keypair(zeus_keypair)


    # Validation and generation of trustees

    def create_trustees(self):
        """
        """
        _, _, _, trustees, _, _ = self.extract_config()
        trustees = self.deserialize_trustees(trustees)

        validated_trustees = dict()
        validate_trustee = self.validate_trustee
        extract_public_key = self.extract_public_key
        for trustee in trustees:
            try:
                validate_trustee(trustee)
            except InvalidTrusteeError:
                raise
            public_key, proof = extract_public_key(trustee)
            validated_trustees.update({
                public_key: proof
            })

        self.set_trustees(validated_trustees)


    def validate_trustee(self, trustee):
        """
        """
        if not self.validate_public_key(trustee):
            public_key = self.get_key_value(trustee).to_hex()
            err = f"Detected invalid trustee: {public_key}"
            raise InvalidTrusteeError(err)


    def deserialize_trustees(self, trustees):
        """
        """
        extract_public_key = self.extract_public_key
        deserialize_public_key = self.deserialize_public_key

        trustees_deserialized = []
        append = trustees_deserialized.append
        for trustee in trustees:
            trustee = deserialize_public_key(trustee)
            append(trustee)
        return trustees_deserialized


    def reprove_trustee(self, public_key, proof):
        """
        """
        pass


    def add_trustee(self, public_key, proof):
        """
        """
        pass


    # Election key generation

    def create_election_key(self):
        """
        """
        election_key = self.compute_election_key()
        self.set_election_key(election_key)


    def compute_election_key(self):
        """
        """
        zeus_public_key = self.get_zeus_public_key()
        zeus_public_key = self.get_key_value(zeus_public_key)   # Ignore proof

        trustees_keys = self.get_trustees()
        public_shares = self.get_public_shares(trustees_keys)   # Ignore proofs

        election_key = self.combine_public_keys(zeus_public_key, public_shares)
        return election_key


    def get_public_shares(self, trustees):
        """
        """
        get_key_value = self.get_key_value
        return (get_key_value(public_key) for public_key in trustees.keys())


    # Validation and creation of candidates

    def create_candidates(self):
        """
        """
        _, _, _, _, candidates, _ = self.extract_config()

        if not candidates:
            err = "Zero number of candidates provided"
            raise InvalidCandidatesError(err)

        validate_candidate = self.validate_candidate
        validated_candidates = []
        append = validated_candidates.append
        for candidate in candidates:
            try:
                validate_candidate(candidate, validated_candidates)
            except InvalidCandidatesError:
                raise
            append(candidate)

        self.set_candidates(validated_candidates)


    def validate_candidate(self, candidate, validated_candidates):
        """
        """
        if candidate in validated_candidates:
            err = "Duplicate candidate detected"
            raise InvalidCandidatesError(err)
        if '%' in candidate:
            err = "Candidate name cannot contain character '%'"
            raise InvalidCandidatesError(err)
        if '\n' in candidate:
            err = "Candidate name cannot contain character '\\n'"
            raise InvalidCandidatesError(err)


    # Validation and creation of voters and audit-codes

    def create_voters_and_audit_codes(self, voter_slot_ceil=VOTER_SLOT_CEIL):
        """
        """
        _, _, _, _, _, voters = self.extract_config()

        if not voters:
            err = "Zero number of voters provided"
            raise InvalidVotersError(err)
        nr_voter_names = len(set(_[0] for _ in voters))
        if nr_voter_names != len(voters):
            err = "Duplicate voter names"
            raise InvalidVotersError(err)
        new_voters = {}
        audit_codes = {}
        random_hex = lambda ceil: '%x' % random_integer(2, ceil)
        for name, weight in voters:
            voter_key = random_hex(VOTER_KEY_CEIL)
            while voter_key in new_voters:
                # ~ Avoid duplicate voter keys. Note for dev:
                # ~ This may lead to infinite loop for small values
                # ~ of VOTER_KEY_CEIL! (not the case in production)
                voter_key = random_hex(VOTER_KEY_CEIL)
            voter_audit_codes = list(random_hex(voter_slot_ceil) for _ in range(3))
            new_voters[voter_key] = (name, weight)
            audit_codes[voter_key] = voter_audit_codes
        audit_code_set = set(tuple(values) for values in audit_codes.values())
        if len(audit_code_set) < 0.5 * len(new_voters):
            err = "Insufficient slot variation attained"
            raise InvalidVotersError(err)
        self.set_voters(new_voters)
        self.set_audit_codes(audit_codes)


    # Vote casting

    def cast_vote(self, vote):
        """
        """
        try:
            vote = self.adapt_vote(vote)
        except InvalidVoteError as err:
            # (1) Wrong or extra or missing fields, or
            # (2) Malformed encrypted ballot, or
            # (3) Cryptosystem mismatch, or
            # (4) Election key mismatch
            raise VoteRejectionError(err)

        (_, _, voter_key, _, fingerprint, voter_audit_code, voter_secret,
            _, _, _, _) = self.extract_vote(vote)

        try:
            voter, voter_audit_codes = self.detect_voter(voter_key)
        except VoteRejectionError:
            # (1) Voter's key not detected, or
            # (2) Not assigned any audit-codes
            raise

        if voter_secret:
            try:
                signature = self.submit_audit_vote(vote, voter_key, fingerprint,
                    voter_audit_code, voter_audit_codes)
            except VoteRejectionError:
                # (1) No audit-code has been provided, or
                # (2) Provided audit-code not among the assigned ones, or
                # (3) No audit-request found for the provided fingerprint, or
                # (4) Vote failed to be verified as audit
                raise
        else:
            # ~ If no audit-code provided, choose one of the assigned ones (rejects
            # ~ if no audit-code has been provided while skip-audit mode dispabled)
            voter_audit_code = self.fix_audit_code(voter_audit_code, voter_audit_codes)
            if voter_audit_code not in voter_audit_codes:
                try:
                    signature = self.submit_audit_request(fingerprint, voter_key, vote)
                except VoteRejectionError:
                    # Audit-request already submitted for the provided fingerprint
                    raise
            else:
                try:
                    signature = self.submit_genuine_vote(fingerprint, voter_key, vote)
                except VoteRejectionError:
                    # (1) Vote already cast, or
                    # (2) Vote limit reached, or
                    # (3) Vote failed to be validated
                    raise
        return signature


    # Mixing preparations

    def load_votes_for_mixing(self):
        """
        Formats the list of submitted votes as an initial cipher-mix
        """
        unmixed_votes = {}
        unmixed_votes.update({'header': self.get_mixnet_header()})

        excluded_votes = set()
        excluded_voters = self.get_excluded_voters()
        update = excluded_votes.update
        get_cast_votes = self.get_cast_votes
        for voter_key, reason in excluded_voters.items():
            update(get_cast_votes(voter_key))

        cast_vote_index = self.get_cast_vote_index()
        get_voter = self.get_voter
        get_vote = self.get_vote
        vote_count = 0
        nr_votes = len(cast_vote_index)
        scratch = list([None]) * nr_votes
        counted = list([None]) * nr_votes
        for i, fingerprint in enumerate(cast_vote_index):
            vote = get_vote(fingerprint)
            index = vote['index']
            # if i != index:
            #     err = f'Vote index mismatch {i} != {index}'
            #     raise AssertionError(err)                                     # Testing
            if fingerprint in excluded_votes:
                continue
            voter_key = vote['voter']
            voter_name, voter_weight = get_voter(voter_key)
            enc_ballot = vote['encrypted_ballot']['ciphertext']
            _vote = (enc_ballot['alpha'], enc_ballot['beta'], voter_weight)
            scratch[i] = _vote
            counted[i] = fingerprint
            previous = vote['previous']
            if not previous:
                vote_count += 1
                continue
            previous_vote = get_vote(previous)
            previous_index = previous_vote['index']
            # if previous_index >= index or scratch[previous_index] is None:
            #     err = 'Inconsistent index!'
            #     raise AssertionError(err)                                     # Testing
            # if previous_vote['voter'] != vote['voter']:
            #     err = f" mismatch: {vote['voter']} vs {previous_vote['voter']}"
            #     raise AssertionError(err)                                     # Testing
            scratch[previous_index] = None
            counted[previous_index] = None

        votes_for_mixing = []
        counted_list = []
        counted_votes = 0
        extend_votes_for_mixing = votes_for_mixing.extend
        extend_counted_list = counted_list.extend
        for c, v in zip(counted, scratch):
            if (c, v) == (None, None):
                continue
            # elif None in (c, v):
            #     raise AssertionError()                                        # Testing
            counted_votes += 1
            alpha, beta, weight = v
            vote = (alpha, beta)
            extend_votes_for_mixing(repeat(vote, weight))
            extend_counted_list(repeat(c, weight))
        # if counted_votes != vote_count:
        #     err = f'Vote count mismatch: {counted_votes} != {vote_count}'
        #     raise AssertionError(err)                                         # Testing
        unmixed_votes.update({
            'original_ciphers': votes_for_mixing,
            'mixed_ciphers': votes_for_mixing,
        })
        return unmixed_votes, counted_list


    # Decryption

    def generate_zeus_factors(self):
        """
        """
        self.generate_factor_colletion()


    def validate_trustee_factors(self, trustee, factors):
        """
        """
        mixed_ballots = self.get_mixed_ballots()
        try:
            self.validate_factor_collection(mixed_ballots, trustee, factors)
        except InvalidFactorsError:
            raise


    def decrypt_ballots(self, mixed_ballots, all_factors):
        """
        """
        decrypted_ballots = self.decrypt_ciphers(mixed_ballots, all_factors)
        return decrypted_ballots
