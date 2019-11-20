"""
"""
import json
from copy import deepcopy

from clients import Trustee, Voter
from tests.election.utils import adapt_vote, extract_vote, display_json
from zeus_core.crypto import mk_cryptosys
from zeus_core.utils import (random_integer, random_selection,
    gamma_encoding_max, random_party_selection, hash_nums, encode_selection)
from zeus_core.election.interfaces.key_manager import KeyManager
from zeus_core.election.interfaces.factor_managers import FactorGenerator
from zeus_core.election.constants import VOTER_SLOT_CEIL


class TrusteeEmulator(Trustee):
    """
    """
    trustee_publics = 'tests/election/emulators/trustee-publics.json'
    trustee_secrets = 'tests/election/emulators/trustee-secrets.json'


    @classmethod
    def get_from_public(cls, crypto_config, public_key):
        """
        """
        public_key, proof, index = cls.locate_trustee(public_key)
        private_key = cls.locate_secret(index)
        keypair = cls.retrieve_keypair(crypto_config, private_key, public_key, proof)

        trustee = cls(crypto_config, keypair)
        return trustee


    @classmethod
    def locate_trustee(cls, public_key):
        """
        """
        with open(cls.trustee_publics) as __file:
            trustees = json.load(__file)
        index = cls.get_trustee_index(trustees, public_key)
        proof = trustees[index]['proof']
        return public_key, proof, index


    @classmethod
    def locate_secret(cls, index):
        """
        """
        with open(cls.trustee_secrets) as __file:
            trustee_secrets = json.load(__file)
        return trustee_secrets[index]


    @classmethod
    def retrieve_keypair(cls, crypto_config, private_key, public_key, proof):
        """
        """
        cryptosys = mk_cryptosys(crypto_config)

        keypair = {}
        private = cryptosys.int_to_exponent(private_key)
        keypair['private'] = private
        public = {}
        proof = cryptosys.deserialize_schnorr_proof(proof)
        public.update({'value': public_key, 'proof': proof})
        keypair['public'] = public
        return keypair


    @classmethod
    def get_trustee_index(cls, trustees, public_key):
        """
        """
        nr_trustees = len(trustees)
        index = (i for i in range(nr_trustees) if public_key.value \
                        == trustees[i]['value']).__next__()
        return index


    # Trustee implementation

    def recv_mixed_ballots(self, mixed_ballots):
        """
        """
        self.store_ciphers(mixed_ballots)
        self.generate_factor_colletion()


    def send_trustee_factors(self, election_server):
        """
        """
        factor_collection = self.get_factor_collection()
        serialized = self.serialize_factor_collection(factor_collection)
        return serialized


class VoterEmulator(Voter):
    """
    """

    def __init__(self, election_params, voter_params):
        """
        """
        crypto_config, election_key, candidates = \
            self.extract_election_params(election_params)
        voter_key, audit_codes = self.extract_voter_params(voter_params)
        super().__init__(crypto_config)
        self.set_election_params(election_key, candidates)
        self.set_voter_params(voter_key, audit_codes)


    @staticmethod
    def extract_election_params(election_params):
        """
        """
        crypto_config = election_params['crypto_config']
        election_key = election_params['election_key']
        candidates = election_params['candidates']

        return crypto_config, election_key, candidates


    @staticmethod
    def extract_voter_params(voter_params):
        """
        """
        voter_key = voter_params['voter_key']
        audit_codes = voter_params.get('audit_codes', None)

        return voter_key, audit_codes


    def set_election_params(self, election_key, candidates):
        """
        """
        self.election_key = election_key
        self.candidates = candidates


    def set_voter_params(self, voter_key, audit_codes):
        """
        """
        self.voter_key = voter_key
        self.audit_codes = audit_codes


    def get_election_key(self):
        """
        """
        return self.election_key


    def get_nr_candidates(self):
        """
        """
        return len(self.candidates)


    def get_voter_key(self):
        """
        """
        return self.voter_key


    def get_audit_codes(self):
        """
        """
        return self.audit_codes


    def mk_genuine_vote(self, corrupt_proof=False, corrupt_fingerprint=False,
            election_mismatch=False):
        """
        Audit code among the assigned ones. Voter's secret not advertised.
        """
        vote = self.mk_random_vote(selection=None,
            audit_code=None, publish=None)
        if corrupt_proof:
            enc_ballot = vote['encrypted_ballot']
            challenge = enc_ballot['challenge']
            response = enc_ballot['response']
            enc_ballot['challenge'] = response
            enc_ballot['response'] = challenge
        if corrupt_fingerprint:
            vote['fingerprint'] += '__corrupt_part'
        if election_mismatch:
            vote['encrypted_ballot']['public'] += 1
        return vote


    def mk_audit_request(self, selection=None, election_mismatch=False):
        """
        Make audit-vote without advertising voter's secret
        """
        audit_request = self.mk_audit_vote(publish=False,
            election_mismatch=election_mismatch)
        return audit_request


    def mk_audit_vote(self, publish=True, missing=False, corrupt_proof=False,
            corrupt_alpha=False, election_mismatch=False, corrupt_encoding=False,
            fake_nr_candidates=None):
        """
        Voter's secret by default advertised
        """
        random_hex = lambda: '%x' % random_integer(2, VOTER_SLOT_CEIL)
        audit_code = random_hex()
        while audit_code in self.get_audit_codes():
            audit_code = random_hex()
        if corrupt_encoding:
            audit_vote = self.mk_corrupt_encoding(fake_nr_candidates, audit_code)
        else:
            audit_vote = self.mk_random_vote(selection=None,
                    audit_code=audit_code, publish=publish)
            enc_ballot = audit_vote['encrypted_ballot']
            if missing:
                del audit_vote['voter_secret']
            if corrupt_proof:
                challenge = enc_ballot['challenge']
                response = enc_ballot['response']
                enc_ballot['challenge'] = response
                enc_ballot['response'] = challenge
            if corrupt_alpha:
                beta = enc_ballot['beta']
                enc_ballot['alpha'] = beta
            if election_mismatch:
                enc_ballot['public'] += 1
        return audit_vote


    def mk_corrupt_encoding(self, fake_nr_candidates, audit_code):
        """
        Meant to be used for testing audit-vote submission: make sure
        that the provided audit_code is not None
        """
        cryptosys = self.get_cryptosys()

        def get_decrypted_value(adapted_vote):
            _, _, _, encrypted_ballot, _, _, voter_secret, _, _, _, _ = \
                extract_vote(adapted_vote)
            ciphertext, _ = cryptosys.extract_ciphertext_proof(encrypted_ballot)
            election_key = self.get_election_key()
            decrypted = cryptosys.decrypt_with_randomness(ciphertext,
                election_key, voter_secret).value
            return decrypted

        audit_vote = self.mk_random_vote(selection=None,
                            audit_code=audit_code, publish=True)
        copy = deepcopy(audit_vote)
        adapted_vote = adapt_vote(cryptosys, copy)
        while get_decrypted_value(adapted_vote) <= \
            gamma_encoding_max(fake_nr_candidates):
            audit_vote = self.mk_random_vote(selection=None,
                            audit_code=audit_code, publish=True)
            copy = deepcopy(audit_vote)
            adapted_vote = adapt_vote(cryptosys, copy)
        return audit_vote


    def mk_random_vote(self, selection, audit_code, publish,
            nr_candidates=None):
        """
        """
        if nr_candidates is None:
            nr_candidates = self.get_nr_candidates()
        if selection is None:
            if random_integer(0, 4) & 1:
                selection = random_selection(nr_candidates, full=False)
            else:
                selection = random_party_selection(nr_candidates, 2)
        encoded_selection = encode_selection(selection, nr_candidates)
        vote = self.mk_vote_from_encoded_selection(encoded_selection,
                audit_code, publish)
        voter_secret = vote.get('voter_secret')
        if voter_secret and not publish:
            del vote['voter_secret']
        return vote


    def mk_vote_from_encoded_selection(self, encoded_selection,
            audit_code, publish):
        """
        """
        cryptosys = self.get_cryptosys()

        encode_integer = cryptosys.encode_integer
        algebraized_selection = encode_integer(encoded_selection)
        vote = self.mk_vote_from_element(algebraized_selection,
                audit_code, publish)
        return vote


    def mk_vote_from_element(self, group_element, audit_code, publish):
        """
        """
        cryptosys = self.get_cryptosys()
        election_key = self.get_election_key()

        ciphertext, randomness = cryptosys.encrypt(group_element,
                        election_key, get_secret=True)
        proof = cryptosys.prove_encryption(ciphertext, randomness)
        encrypted_ballot = self.mk_encrypted_ballot(ciphertext, proof)
        fingerprint = self.mk_fingerprint(encrypted_ballot)
        voter_secret = int(randomness) if publish else None
        vote = self.set_vote(encrypted_ballot, fingerprint, audit_code,
            publish, voter_secret)
        return vote


    def set_vote(self, encrypted_ballot, fingerprint, audit_code=None,
            publish=None, voter_secret=None, previous=None, index=None,
            status=None, plaintext=None):
        """
        """
        vote = {}
        vote['voter'] = self.get_voter_key()
        vote['encrypted_ballot'] = encrypted_ballot
        vote['fingerprint'] = fingerprint
        if audit_code:
            vote['audit_code'] = audit_code
        if publish:
            vote['voter_secret'] = voter_secret
        return vote


    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        """
        cryptosys = self.get_cryptosys()
        election_key = self.get_election_key()

        encrypted_ballot = {}
        encrypted_ballot.update(cryptosys.parameters())
        encrypted_ballot.update({'public': election_key.to_int()})

        ciphertext = cryptosys.serialize_ciphertext(ciphertext)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        encrypted_ballot.update({
            'alpha': alpha,
            'beta': beta
        })

        proof = cryptosys.serialize_scnorr_proof(proof)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
        encrypted_ballot.update({
            'commitment': commitment,
            'challenge': challenge,
            'response': response,
        })

        return encrypted_ballot


    def mk_fingerprint(self, encrypted_ballot):
        """
        """
        params = self.get_fingerprint_params(encrypted_ballot)
        fingerprint = hash_nums(*params).hex()
        return fingerprint


    def get_fingerprint_params(self, encrypted_ballot):
        """
        """
        alpha = encrypted_ballot['alpha']
        beta = encrypted_ballot['beta']
        commitment = encrypted_ballot['commitment']
        challenge = encrypted_ballot['challenge']
        response = encrypted_ballot['response']

        return alpha, beta, commitment, challenge, response