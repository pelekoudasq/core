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
        self.zeus_public_key = zeus_public_key
        self.election_key = election_key
        self.trustees = trustees
        self.candidates = candidates
        self.voter_key = voter_key
        self.audit_codes = audit_codes
        self.cryptosys = self.retrieve_cryptosys(crypto)

    @classmethod
    def retrieve_cryptosys(cls, crypto):
        """
        """
        cls = crypto['cls']
        config = crypto['config']
        cryptosys = make_crypto(cls, config)
        return cryptosys


    # Vote making

    def mk_encrypted_ballot(self, ciphertext, proof):
        """
        """
        encrypted_ballot = self.cryptosys.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot

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
        """
        params = self.get_fingerprint_params(encrypted_ballot)
        fingerprint = hash_texts(*[str(_) for _ in params])
        return fingerprint

    def set_vote(self, encrypted_ballot, fingerprint, audit_code=None,
            publish=None, voter_secret=None, previous=None, index=None,
            status=None, plaintext=None):
        """
        """
        vote = {}

        vote['crypto'] = self.cryptosys.parameters()
        vote['public'] = self.election_key
        vote['voter'] = self.voter_key
        vote['encrypted_ballot'] = encrypted_ballot
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

        ciphertext, randomness = cryptosys._encrypt(group_element,
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


    # Vote textification: CONTINUE FROM HERE

    def extract_encrypted_ballot(self, encrypted_ballot):
        """
        """
        cryptosys = self.cryptosys
        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)

        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_proof(proof)

        return alpha, beta, commitment, challenge, response

    def extract_vote(self, vote, encode_func, to_exponent=int):
        """
        """
        crypto_params = vote['crypto']
        election_key = vote['public']
        voter_key = vote['voter']
        alpha, beta, commitment, challenge, response = \
            self.extract_encrypted_ballot(vote['encrypted_ballot'])
        fingerprint = hash_encode(vote['fingerprint'])

        audit_code = extract_value(vote, 'audit_code', int)
        voter_secret = extract_value(vote, 'voter_secret', to_exponent) # mpz
        previous = extract_value(vote, 'previous', hash_encode)
        index = extract_value(vote, 'index', int)
        status = extract_value(vote, 'status', str)
        plaintext = extract_value(vote, 'plaintext', encode_func)

        return (crypto_params, election_key, voter_key, alpha, beta, commitment,
                challenge, response, fingerprint, audit_code, voter_secret,
                previous, index, status, plaintext,)

    def textify_vote(self, vote, comments):
        """
        """

        (crypto_params, election_key, _, alpha, beta, commitment, challenge, response,
            fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)

        t00 = status if status is not None else 'NONE'
        t01 = V_FINGERPRINT + '%s' % fingerprint
        t02 = V_INDEX + '%d' % (index if index is not None else 'NONE')
        t03 = V_PREVIOUS + '%s' % (previous,) 	# '%s%s' % (V_PREVIOUS, previous)
        t04 = V_ELECTION + '%s' % str(election_key)
        t05 = V_ZEUS_PUBLIC + '%s' % str(zeus_public_key)
        t06 = V_TRUSTEES + '%s' % ' '.join(str(_) for _ in trustees)
        t07 = V_CANDIDATES + '%s' % ' % '.join('%s' % _.encode('utf-8') for _ in candidates)

        t08, t09, t10 = cryptosys.textify_params(crypto_params)

        t11 = V_ALPHA + '%s' % str(alpha)
        t12 = V_BETA + '%s' % str(beta)
        t13 = V_COMMITMENT + '%s' % str(commitment)
        t14 = V_CHALLENGE + '%s' % str(challenge)
        t15 = V_RESPONSE + '%s' % str(response)
        t16 = V_COMMENTS + '%s' % (comments,)

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
            t09, t10, t11, t12, t13, t14, t15, t6))
        return textified


    # Vote signing

    # Vote casting
