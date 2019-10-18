"""
Client reference
"""
from json import dumps

from zeus_core.crypto import mk_cryptosys
from zeus_core.utils import (random_integer, random_selection,
    random_party_selection, hash_nums, encode_selection)
from zeus_core.elections.constants import VOTER_SLOT_CEIL

class Client(object):
    """
    """

    def __init__(self, config_crypto, election_key, nr_candidates,
                    voter_key, audit_codes=None):
        """
        """
        self.cryptosys = self.retrieve_cryptosys(config_crypto)
        self.election_key = election_key
        self.nr_candidates = nr_candidates
        self.voter_key = voter_key
        self.audit_codes = audit_codes

    @classmethod
    def retrieve_cryptosys(cls, config_crypto):
        cls = config_crypto['cls']
        config = config_crypto['config']
        cryptosys = mk_cryptosys(cls, config)
        return cryptosys

    def mk_genuine_vote(self):
        """
        Audit code among the assigned ones. Voter's secret not advertised.
        """
        vote = self.mk_random_vote(selection=None,
            audit_code=None, publish=None)
        return vote

    def mk_audit_request(self, selection=None):
        """
        Audit code not among the assigned ones. Voter's secret not advertised.
        """
        random_hex = lambda:'%x' % random_integer(2, VOTER_SLOT_CEIL)
        audit_code = random_hex()
        while audit_code in self.audit_codes:
            audit_code = random_hex()
        audit_vote = self.mk_random_vote(selection=None,
            audit_code=audit_code, publish=None)
        return audit_vote

    def mk_audit_vote(self):
        """
        Voter's secret advertised
        """
        audit_vote = self.mk_random_vote(selection=None,
            audit_code=None, publish=True)
        return audit_vote

    def mk_random_vote(self, selection, audit_code, publish):
        """
        """
        nr_candidates = self.nr_candidates
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
        encode_integer = self.cryptosys.encode_integer
        algebraized_selection = encode_integer(encoded_selection)
        vote = self.mk_vote_from_element(algebraized_selection,
                audit_code, publish)
        return vote

    def mk_vote_from_element(self, group_element, audit_code, publish):
        """
        """
        cryptosys = self.cryptosys
        election_key = self.election_key

        # ~ Ballot encryption under the election's key (ElGamal), along with proof
        # ~ of knowledge of the randomness (voter's secret) used at encryption
        ciphertext, randomness = cryptosys.encrypt(group_element, election_key,
            get_secret=True)
        proof = cryptosys.prove_encryption(ciphertext, randomness)
        encrypted_ballot = self.mk_encrypted_ballot(ciphertext, proof)

        # Make vote's fingerprint out of encrypted ballot
        fingerprint = self.mk_fingerprint(encrypted_ballot)

        voter_secret = int(randomness) if publish else None
        vote = self.set_vote(encrypted_ballot, fingerprint, audit_code,
            publish, voter_secret)
        return vote

    def set_vote(self, encrypted_ballot, fingerprint, audit_code=None,
            publish=None, voter_secret=None, previous=None, index=None,
            status=None, plaintext=None):
        """
        Accepts serialized, returns serialized
        """
        vote = {}
        vote['voter'] = self.voter_key
        vote['encrypted_ballot'] = encrypted_ballot
        vote['fingerprint'] = fingerprint # hexdigest
        if audit_code:
            vote['audit_code'] = audit_code
        if publish:
            vote['voter_secret'] = voter_secret
        return vote

    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        Accepts non-serialized, returns serialized
        """
        cryptosys = self.cryptosys

        encrypted_ballot = {}
        encrypted_ballot.update(cryptosys.parameters())
        encrypted_ballot.update({'public': self.election_key.to_int()})

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
        Accepts serialized, returns hexdigest
        """
        params = self.get_fingerprint_params(encrypted_ballot)
        fingerprint = hash_nums(*params).hex()
        return fingerprint

    def get_fingerprint_params(self, encrypted_ballot):
        """
        Accepts serialized
        """
        alpha = encrypted_ballot['alpha']
        beta = encrypted_ballot['beta']
        commitment = encrypted_ballot['commitment']
        challenge = encrypted_ballot['challenge']
        response = encrypted_ballot['response']

        return alpha, beta, commitment, challenge, response
