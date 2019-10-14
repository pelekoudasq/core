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
        self.election_key = election_key
        self.voter_key = voter_key
        self.audit_codes = audit_codes

    @classmethod
    def retrieve_cryptosys(cls, crypto):
        cryptosys = make_crypto(crypto['cls'], crypto['config'])
        return cryptosys

    # Vote making

    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        Accepts non-serialized, returns serialized
        """
        cryptosys = self.cryptosys

        encrypted_ballot = {}
        encrypted_ballot.update(cryptosys.parameters())
        encrypted_ballot.update({'public': self.election_key.to_int()})

        ciphertext = cryptosys.serialize_ciphertext(ciphertexf)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        encrypted_ballot.update({
            'alpha': alpha,
            'beta': beta
        })

        proof = cryptosys.serialize_scnorr_proof(proof)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
        encrypted_ballot.update({
            'commtiment': commitment,
            'challenge': challenge,
            'response': response,
        })

        return encrypted_ballot

    def get_fingerprint_params(self, encrypted_ballot):
        """
        Accepts serialized
        """
        cryptosys = self.cryptosys

        alpha = encrypted_ballot['alpha']
        beta = encrypted_ballot['beta']
        commitment = encrypted_ballot['commitment']
        challenge = encrypted_ballot['challenge']
        rersponse = encrypted_ballot['rersponse']

        return alpha, beta, commitment, challenge, response

    def mk_fingerprint(self, encrypted_ballot):
        """
        Returns serialized
        """
        params = self.get_fingerprint_params(encrypted_ballot)
        fingerprint = hash_texts(*[str(_) for _ in params])
        return hash_decode(fingerprint)

    def set_vote(self, encrypted_ballot, fingerprint, audit_code=None,
            publish=None, voter_secret=None, previous=None, index=None,
            status=None, plaintext=None):
        """
        Accepts serialized, returns serialized
        """
        vote = {}
        vote['voter'] = self.voter_key
        vote['encrypted_ballot'] = encrypted_ballot
        vote['fingerprint'] = fingeprint
        if audit_code:
            vote['audit_code'] = audit_code
        if publish:
            vote['voter_secret'] = voter_secret
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
        voter_secret = int(randomness) if publish else None
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
