"""
Client reference
"""

from zeus_core.crypto import make_crypto
from zeus_core.utils import random_integer, hash_texts, hash_encode

PLAINTEXT_CEIL = 2 ** 512

class Client(object):
    """
    """
    pass

class Voter(Client):
    """
    """

    def __init__(self, crypto, zeus_public_key, election_key, trustees,
            candidates, voter_key, audit_codes=None):
        """
        """
        self.cryptosys = self.retrieve_cryptosys(crypto)
        # self.zeus_public_key = zeus_public_key
        self.election_key = election_key
        # self.trustees = trustees
        # self.candidates = candidates
        self.voter_key = voter_key
        self.audit_codes = audit_codes

    @classmethod
    def retrieve_cryptosys(cls, crypto):
        """
        """
        cryptosys = make_crypto(crypto['cls'], crypto['config'])
        return cryptosys


    # Vote making

    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        """
        encrypted_ballot = self.cryptosys.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot

    def serialize_encrypted_ballot(self, encrypted_ballot):
        """
        """
        serialized = self.cryptosys.serialize_ciphertext_proof(encrypted_ballot)
        return serialized

    def get_fingerprint_params(self, encrypted_ballot):
        """
        """
        cryptosys = self.cryptosys

        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)

        return alpha, beta, commitment, challenge, response

    def mk_fingerprint(self, encrypted_ballot):
        """
        Returns bytes
        """
        params = self.get_fingerprint_params(encrypted_ballot)
        fingerprint = hash_texts(*[str(_) for _ in params])
        return fingerprint

    def set_vote(self, encrypted_ballot, fingerprint, audit_code=None,
            publish=None, voter_secret=None, previous=None, index=None,
            status=None, plaintext=None):
        """
        JSON (must serialize everything before setting)
        """
        vote = {}

        vote['crypto'] = self.cryptosys.parameters()
        vote['public'] = self.election_key.to_int()
        vote['voter'] = self.voter_key
        vote['encrypted_ballot'] = self.serialize_encrypted_ballot(encrypted_ballot)
        vote['fingerprint'] = hash_decode(fingerprint)

        if audit_code:
            vote['audit_code'] = audit_code
        if publish:
            vote['voter_secret'] = voter_secret
        if previous:
            vote['index'] = index
        if status:
            vote['status'] = status
        if plaintext:
            vote['plaintext'] = plaintext

        return vote

    def mk_vote_from_element(self, group_element, audit_code=None, publish=None):
        """
        """
        cryptosys = self.cryptosys
        election_key = self.election_key

        # ~ Ballot encryption (ElGamal) under the election's key,
        # ~ along with proof of knowledge of the randomness
        # ~ (voter's secret) used at encryption
        ciphertext, randomness = cryptosys.encrypt(group_element,
                        election_key, get_secret=True)
        proof = cryptosys.prove_encryption(ciphertext, ranodmness)
        encrypted_ballot = self.mk_encrypted_ballot(ciphertext, proof)

        fingerprint = self.mk_fingerprint(encrypted_ballot)
        voter_secret = randomness if publish else None
        vote = self.set_vote(encrypted_ballot, fingerprint, audit_code,
            publish, voter_secret)

        return vote

    def mk_vote_from_plaintext(self, plaintext, audit_code=None, publish=None):
        """
        """
        if not plaintext:
            plaintext = random_integer(2, PLAINTEXT_CEIL)
        encoded_plaintext = self.cryptosys.encode_integer(plaintext)
        return self.mk_vote_from_element(encoded_plaintext,
            audit_code=audit_code, publish=publish)

    def mk_vote_from_encoded_selection(self, encoded_selection, audit_code=None, publish=None):
        """
        """
        algebraized_selection = self.cryptosys.encode_integer(encoded_selection)
        return self.mk_vote_from_element(self, algebraized_selection,
            audit_code=audit_code, publish=publish)

    def mk_random_vote(self, nr_candidates, selection=None, audit_code=None, publish=None):
        """
        """
        if selection is None:
            if random_integer(0, 4) & 1:
                selection = random_selection(nr_candidates, full=False)
            else:
                selection = random_party_selection(nr_candidates, 2)
        encoded_selection = encode_selection(selection, nr_candidates)

        vote = self.mk_vote_from_encoded_selection(encoded_selection,
            audit_code=audit_code, publish=publish)

        voter_secret = vote.get('voter_secret')
        if voter_secret and not publish:
            del vote['voter_secret']

        return vote, selection, encoded_selection, voter_secret
