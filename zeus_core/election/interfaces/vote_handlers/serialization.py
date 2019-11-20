"""
"""

from abc import ABCMeta, abstractmethod

class VoteSerializer(object, metaclass=ABCMeta):
    """
    Serialization/deserialization interface to election server
    """

    def extract_vote(self, vote):
        """
        Assumes vote after adaptement (values deserialized, keys rearranged)
        Fills with None the following fields if missing:
            previous, index, status, plaintext, audit_code, voter_secret
        """
        vote_crypto = vote['crypto']
        vote_election_key = vote['public']
        voter_key = vote['voter']
        encrypted_ballot = vote['encrypted_ballot']
        fingerprint = vote['fingerprint']

        get_value = vote.get
        previous = get_value('previous')
        index = get_value('index')
        status = get_value('status')
        plaintext = get_value('plaintext')
        audit_code = get_value('audit_code')
        voter_secret = get_value('voter_secret')

        return (vote_crypto, vote_election_key, voter_key, encrypted_ballot,
            fingerprint, audit_code, voter_secret, previous, index,
            status, plaintext,)


    # Ballots (de)serialization

    @abstractmethod
    def get_cryptosys(self):
        """
        """

    def serialize_encrypted_ballot(self, encrypted_ballot):
        """
        """
        cryptosys = self.get_cryptosys()

        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)

        alpha = alpha.to_int()
        beta = beta.to_int()
        commitment = commitment.to_int()
        challenge = cryptosys.int_to_exponent(challenge)
        response = cryptosys.int_to_exponent(response)

        return alpha, beta, commitment, challenge, response


    def deserialize_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """
        cryptosys = self.get_cryptosys()

        alpha = cryptosys.int_to_element(alpha)
        beta = cryptosys.int_to_element(beta)
        commitment = cryptosys.int_to_element(commitment)
        challenge = cryptosys.int_to_exponent(challenge)
        response = cryptosys.int_to_exponent(response)

        ciphertext = cryptosys.set_ciphertext(alpha, beta)
        proof = cryptosys.set_schnorr_proof(commitment, challenge, response)

        encrypted_ballot = cryptosys.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot


    def hexify_encrypted_ballot(self, encrypted_ballot):
        """
        """
        cryptosys = self.get_cryptosys()

        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)

        alpha = alpha.to_hex()
        beta = beta.to_hex()
        commitment = commitment.to_hex()
        challenge = cryptosys.exponent_to_hex(challenge)
        response = cryptosys.exponent_to_hex(response)

        return alpha, beta, commitment, challenge, response


    def unhexify_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """
        cryptosys = self.get_cryptosys()

        alpha = cryptosys.hex_to_element(alpha)
        beta = cryptosys.hex_to_element(beta)
        commitment = cryptosys.hex_to_element(commitment)
        challenge = cryptosys.hex_to_exponent(challenge)
        response = cryptosys.hex_to_exponent(response)

        ciphertext = cryptosys.set_ciphertext(alpha, beta)
        proof = cryptosys.set_schnorr_proof(commitment, challenge, response)
        encrypted_ballot = cryptosys.set_ciphertext_proof(ciphertext, proof)

        return encrypted_ballot
