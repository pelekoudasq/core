"""
"""
from abc import ABCMeta, abstractmethod
from zeus_core.election.interfaces.signatures import Verifier
from zeus_core.crypto import mk_cryptosys
from zeus_core.utils import hash_nums
from .generic import Client



class Voter(Client, Verifier, metaclass=ABCMeta):
    """
    """

    def __init__(self, name, weight):
        """
        """
        self.name   = name
        self.weight = weight

        self.election_key = None
        self.candidates  = []
        self.voter_key    = None
        self.audit_codes  = []


    def get_name(self):
        return self.name

    def get_weight(self):
        return self.weight

    def store_election_key(self, election_key):
        self.election_key = election_key

    def get_election_key(self):
        return self.election_key

    def store_candidates(self, candidates):
        self.candidates = candidates

    def get_candidates(self):
        return self.candidates

    def store_voter_key(self, voter_key):
        self.voter_key = voter_key

    def get_voter_key(self):
        return self.voter_key

    def store_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes

    def get_audit_codes(self):
        return self.audit_codes


    # Election parameters

    def extract_election_params(self, params):
        """
        """
        crypto_config = params['crypto']
        cryptosys = mk_cryptosys(crypto_config)
        election_key = params['election_key']
        election_key = cryptosys.int_to_element(election_key)
        candidates = params['candidates']
        voter_key = params['voter_key']
        audit_codes = params['audit_codes']

        return cryptosys, election_key, candidates, voter_key, audit_codes


    def store_election_params(self, cryptosys, election_key, candidates,
                            voter_key, audit_codes):
        """
        """
        self.set_cryptosys(cryptosys)
        self.store_election_key(election_key)
        self.store_candidates(candidates)
        self.store_voter_key(voter_key)
        self.store_audit_codes(audit_codes)


    # Vote generation

    def mk_vote_from_encoded_selection(self, encoded_selection, audit_code,
                                       publish):
        """
        """
        cryptosys = self.get_cryptosys()

        encode_integer = cryptosys.encode_integer
        algebraized_selection = encode_integer(encoded_selection)
        vote = self.mk_vote_from_element(algebraized_selection,
                audit_code, publish)
        return vote


    def mk_vote_from_element(self, element, audit_code, publish):
        """
        """
        cryptosys = self.get_cryptosys()
        election_key = self.get_election_key()

        ciphertext, randomness = cryptosys.encrypt(element,
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
        if audit_code: vote['audit_code'] = audit_code
        if publish: vote['voter_secret'] = voter_secret

        return vote


    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        """
        encrypted_ballot = {}

        cryptosys = self.get_cryptosys()
        encrypted_ballot.update(cryptosys.parameters())

        election_key = self.get_election_key()
        encrypted_ballot['public'] = election_key.to_int()

        ciphertext = cryptosys.serialize_ciphertext(ciphertext)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        encrypted_ballot['alpha'] = alpha
        encrypted_ballot['beta'] = beta

        proof = cryptosys.serialize_schnorr_proof(proof)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
        encrypted_ballot['commitment'] = commitment
        encrypted_ballot['challenge'] = challenge
        encrypted_ballot['response'] = response

        return encrypted_ballot


    def mk_fingerprint(self, encrypted_ballot):
        """
        """
        fingerprint_params = self.extract_fingerprint(encrypted_ballot)
        fingerprint = hash_nums(*fingerprint_params).hex()
        return fingerprint


    def extract_fingerprint(self, encrypted_ballot):
        """
        """
        alpha = encrypted_ballot['alpha']
        beta = encrypted_ballot['beta']
        commitment = encrypted_ballot['commitment']
        challenge = encrypted_ballot['challenge']
        response = encrypted_ballot['response']

        return alpha, beta, commitment, challenge, response
