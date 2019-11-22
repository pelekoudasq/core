from abc import ABCMeta, abstractmethod


__all__ = ('ElGamalCrypto', 'Group', 'GroupElement',)


class GroupElement(object, metaclass=ABCMeta):

    @abstractmethod
    def __repr__(self):
        """
        """

    @abstractmethod
    def __hash__(self):
        """
        """

    @abstractmethod
    def __eq__(self):
        """
        """

    @abstractmethod
    def __mul__(self, other):
        """
        """

    @abstractmethod
    def __pow__(self, exp):
        """
        """

    @property
    @abstractmethod
    def inverse(self):
        """
        """

    @abstractmethod
    def to_int(self):
        """
        """

    @abstractmethod
    def to_hex():
        """
        """

    @abstractmethod
    def contained_in(self, group):
        """
        """


class Group(object, metaclass=ABCMeta):

    @abstractmethod
    def __repr__(self):
        """
        """

    @abstractmethod
    def __hash__(self):
        """
        """

    @property
    @abstractmethod
    def order(self):
        """
        """

    @abstractmethod
    def contains(self, element):
        """
        """


class ElGamalCrypto(metaclass=ABCMeta):
    """
    Abstract class for ElGamal cryptosystems
    """

    @classmethod
    @abstractmethod
    def _validate_system(cls, *params):
        """
        """

    @classmethod
    @abstractmethod
    def _extract_config(cls, config):
        """
        """

    # --------------------------------- System ---------------------------------

    @abstractmethod
    def parameters(self):
        """
        """

    @abstractmethod
    def hex_parameters(self):
        """
        """

    @abstractmethod
    def _parameters(self):
        """
        """

    @property
    @abstractmethod
    def group(self):
        """
        """

    @property
    @abstractmethod
    def GroupElement(self):
        """
        """

    @abstractmethod
    def validate_element(self, element):
        """
        """

    @abstractmethod
    def generate_keypair(self, private_key=None):
        """
        """

    # ---------------- (De)serialization of algebraic entities -----------------

    @abstractmethod
    def int_to_exponent(self, integer):
        """
        """

    @abstractmethod
    def hex_to_exponent(self, hex_string):
        """
        """

    @abstractmethod
    def exponent_to_int(self, exponent):
        """
        """

    @abstractmethod
    def exponent_to_hex(self, exponent):
        """
        """

    @abstractmethod
    def int_to_element(self, integer):
        """
        """

    @abstractmethod
    def hex_to_element(self, hex_string):
        """
        """

    @abstractmethod
    def encode_integer(self, integer):
        """
        """

    # ----------------------------- Election utils -----------------------------

    # Vote validation and signing

    @abstractmethod
    def mk_hex_labels(self, crypto_params):
        """
        """

    @abstractmethod
    def check_labels(self, t08, t09, t10):
        """
        """

    @abstractmethod
    def hexify_crypto_params(self, params):
        """
        """

    @abstractmethod
    def unhexify_crypto_params(self, t08, t09, t10):
        """
        """


    # ------------------------------- Primitives -------------------------------

    # Schnorr protocol

    ############################################################
    #                                                          #
    #    By Schnorr-proof is meant a dictionary of the form    #
    #                                                          #
    #    {                                                     #
    #       'commitment': GroupElement                         #
    #       'challenge': exponent                              #
    #       'response': exponent                               #
    #    }                                                     #
    #                                                          #
    ############################################################


    def set_schnorr_proof(self, commitment, challenge, response):
        """
        """
        proof = {}

        proof['commitment'] = commitment
        proof['challenge'] = challenge
        proof['response'] = response

        return proof


    def extract_schnorr_proof(self, proof):
        """
        """
        commitment = proof['commitment']
        challenge = proof['challenge']
        response = proof['response']

        return commitment, challenge, response


    def serialize_schnorr_proof(self, proof):
        """
        """
        serialized = {}
        if proof is not None:
            commitment, challenge, response = self.extract_schnorr_proof(proof)
            serialized['commitment'] = commitment.to_int()
            serialized['challenge'] = self.exponent_to_int(challenge)
            serialized['response'] = self.exponent_to_int(response)
        return serialized



    def deserialize_schnorr_proof(self, proof):
        """
        """
        deserialized = {}
        commitment, challenge, response = self.extract_schnorr_proof(proof)

        deserialized['commitment'] = self.int_to_element(commitment)
        deserialized['challenge'] = self.int_to_exponent(challenge)
        deserialized['response'] = self.int_to_exponent(response)

        return deserialized


    @abstractmethod
    def _schnorr_proof(self, secret, public, *extras):
        """
        Schnorr protocol implementation from the prover's side (non-interactive)
        """


    @abstractmethod
    def _schnorr_verify(self, proof, public, *extras):
        """
        Schnorr protocol implementation from the verifier's side (non-interactive)
        """


    # Chaum-Pedersen protocol

    ###################################################################
    #                                                                 #
    #    By Chaum-Pedersen proof is meant a dictionary of the form    #
    #                                                                 #
    #    {                                                            #
    #        'base_commitment': GroupElement                          #
    #        'message_commitment': GroupElement                       #
    #        'challenge': exponent                                    #
    #        'response': exponent                                     #
    #    }                                                            #
    #                                                                 #
    ###################################################################


    def _set_chaum_pedersen_proof(self, base_commitment, message_commitment,
            challenge, response):
        """
        """
        proof = {}

        proof['base_commitment'] = base_commitment
        proof['message_commitment'] = message_commitment
        proof['challenge'] = challenge
        proof['response'] = response

        return proof


    def extract_chaum_pedersen_proof(self, proof):
        """
        """
        base_commitment = proof['base_commitment']
        message_commitment = proof['message_commitment']
        challenge = proof['challenge']
        response = proof['response']

        return base_commitment, message_commitment, challenge, response


    def serialize_chaum_pedersen_proof(self, proof):
        """
        """
        serialized = {}

        base_commitment, message_commitment, challenge, response = \
            self.extract_chaum_pedersen_proof(proof)
        serialized['base_commitment'] = base_commitment.to_int()
        serialized['message_commitment'] = message_commitment.to_int()
        serialized['challenge'] = self.exponent_to_int(challenge)
        serialized['response'] = self.exponent_to_int(response)

        return serialized


    def deserialize_chaum_pedersen_proof(self, proof):
        """
        """
        deserialized = {}

        base_commitment, message_commitment, challenge, response = \
            self.extract_chaum_pedersen_proof(proof)
        deserialized['base_commitment'] = self.int_to_element(base_commitment)
        deserialized['message_commitment'] = self.int_to_element(message_commitment)
        deserialized['challenge'] = self.int_to_exponent(challenge)
        deserialized['response'] = self.int_to_exponent(response)

        return deserialized


    @abstractmethod
    def _chaum_pedersen_proof(self, ddh, z):
        """
        Chaum-Pedersen protocol implementation from the prover's side (non-interactive)
        """


    @abstractmethod
    def _chaum_pedersen_verify(self, ddh, proof):
        """
        Chaum-Pedersen protocol implementation from the verifier's side (non-interactive)
        """


    # Digital Signature Algorithm (low-level DSA)

    ############################################################
    #                                                          #
    #    By DSA-signature is meant a dictionary of the form    #
    #                                                          #
    # 	 {                                                     #
    #        'exponent': exponent,                             #
    #        'commitments': {                                  #
    #            'c_1': exponent,                              #
    #            'c_2': exponent                               #
    #        }                                                 #
    # 	 }                                                     #
    #                                                          #
    ############################################################


    def set_dsa_signature(self, exponent, c_1, c_2):
        """
        """
        signature = {}
        signature['exponent'] = exponent
        signature['commitments'] = {'c_1': c_1, 'c_2': c_2}

        return signature


    def extract_dsa_signature(self, signature):
        """
        """
        exponent = signature['exponent']
        commitments = signature['commitments']
        c_1 = commitments['c_1']
        c_2 = commitments['c_2']

        return exponent, c_1, c_2


    def hexify_dsa_signature(self, signature):
        """
        """
        exp, c_1, c_2 = self.extract_dsa_signature(signature)

        exp = self.exponent_to_hex(exp)
        c_1 = self.exponent_to_hex(c_1)
        c_2 = self.exponent_to_hex(c_2)

        return f'{exp}\n{c_1}\n{c_2}'


    def unhexify_dsa_signature(self, hex_signature):
        """
        """
        exp, c_1, c_2 = hex_signature.split('\n')

        exp = self.hex_to_exponent(exp)
        c_1 = self.hex_to_exponent(c_1)
        c_2 = self.hex_to_exponent(c_2)

        unhexified = self.set_dsa_signature(exp, c_1, c_2)
        return unhexified


    @abstractmethod
    def _dsa_signature(self, exponent, private_key):
        """
        """

    @abstractmethod
    def _dsa_verify(self, exponent, signature, public_key):
        """
        """


    # Text-message signatures (high-level DSA)

    #####################################################################
    #                                                                   #
    #    By signed message is meant a dictionary of the form            #
    #                                                                   #
    #    {                                                              #
    #        'message': str,                                            #
    #        'signature': {                                             #
    #            'exponent': exponent,                                  #
    #            'commitments': {                                       #
    #               'c_2': exponent                                     #
    #               'c_1': exponent,                                    #
    #             }                                                     #
    #         }                                                         #
    #     }                                                             #
    #                                                                   #
    #####################################################################


    def set_signed_message(self, message, signature):
        """
        """
        signed_message = {}
        signed_message['message'] = message
        signed_message['signature'] = signature
        return signed_message


    def extract_signed_message(self, signed_message):
        """
        """
        message = signed_message['message']
        signature = signed_message['signature']
        return message, signature


    @abstractmethod
    def sign_text_message(self, message, private_key):
        """
        """

    @abstractmethod
    def verify_text_signature(self, signed_message, public_key):
        """
        """


    # ElGamal encryption/decryption

    #########################################################
    #                                                       #
    #    By ciphertext is meant a dictionary of the form    #
    #                                                       #
    #    {                                                  #
    #        'alpha': GroupElement                          #
    #        'beta': GroupElement                           #
    #    }                                                  #
    #                                                       #
    #########################################################


    def set_ciphertext(self, alpha, beta):
        """
        """
        ciphertext = {}
        ciphertext['alpha'] = alpha
        ciphertext['beta'] = beta

        return ciphertext


    def extract_ciphertext(self, ciphertext):
        """
        """
        alpha = ciphertext['alpha']
        beta = ciphertext['beta']

        return alpha, beta


    def serialize_ciphertext(self, ciphertext):
        """
        """
        serialized = {}

        alpha, beta = self.extract_ciphertext(ciphertext)
        serialized['alpha'] = alpha.to_int()
        serialized['beta'] = beta.to_int()

        return serialized


    def set_ciphertext_proof(self, ciphertext, proof):
        """
        """
        ciphertext_proof = {}

        ciphertext_proof['ciphertext'] = ciphertext
        ciphertext_proof['proof'] = proof

        return ciphertext_proof


    def extract_ciphertext_proof(self, ciphertext_proof):
        """
        """
        ciphertext = ciphertext_proof['ciphertext']
        proof = ciphertext_proof['proof']

        return ciphertext, proof


    def serialize_ciphertext_proof(self, ciphertext_proof):
        """
        """
        serialized = {}

        ciphertext, proof = self.extract_ciphertext_proof(ciphertext_proof)
        serialized['ciphertext'] = self.serialize_ciphertext(ciphertext)
        serialized['proof'] = self.serialize_schnorr_proof(proof)

        return serialized


    def prove_encryption(self, ciphertext, randomness):
        """
        Generates ZK (Schnorr) proof-of-knowledge of the randomness involved
        in the ElGamal encryption that yields the provided ciphertext
        """
        alpha, beta = self.extract_ciphertext(ciphertext)
        proof = self._schnorr_proof(randomness, alpha, beta)

        return proof


    def verify_encryption(self, ciphertext_proof):
        """
        Verifies ZK (Schnorr) proof-of-knowledge of the randomness used
        in the ElGamal encryption that yields the provided ciphertext
        """
        ciphertext, proof = self.extract_ciphertext_proof(ciphertext_proof)
        alpha, beta = self.extract_ciphertext(ciphertext)
        verified = self._schnorr_verify(proof, alpha, beta)

        return verified


    @abstractmethod
    def encrypt(self, element, public_key, randomness=None, get_secret=False):
        """
        """

    @abstractmethod
    def decrypt(self, ciphertext, private_key):
        """
        """

    @abstractmethod
    def reencrypt(self, ciphertext, public_key, randomness=None, get_secret=False):
        """
        """

    @abstractmethod
    def decrypt_with_decryptor(self, ciphertext, decryptor):
        """
        """

    @abstractmethod
    def decrypt_with_randomness(self, ciphertext, public, secret):
        """
        """
