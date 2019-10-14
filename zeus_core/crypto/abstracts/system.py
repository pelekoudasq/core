from abc import ABCMeta, abstractmethod

class KeyManager(object, metaclass=ABCMeta):
    """
    Key-management interface
    """

    @abstractmethod
    def keygen(self, private_key=None):
        """
        Generates and returns a keypair
        """

    def _set_keypair(self, private_key, public_key):
        """
        :type private_key: mpz
        :type public_key: dict
        :rtype: dict
        """
        keypair = {'private': private_key, 'public': public_key}
        return keypair

    def extract_keypair(self, keypair):
        """
        Returns a tuple with the private and public part of the provided key in
        the form of a numerical value (mpz) and a dict respectively

        :type keypair: dict
        :rtype: (mpz, dict)
        """
        return keypair['private'], keypair['public']

    def _get_private(self, keypair):
        """
        :type keypair: dict
        :rtype: mpz
        """
        return keypair['private']

    def _get_public(self, keypair):
        """
        :type keypair:
        :rtype: dict
        """
        return keypair['public']

    @abstractmethod
    def validate_public_key(self, public_key):
        """
        """

    def _get_public_value(self, keypair):
        """
        :type keypair: dict
        :rtype: ModPrimeElement
        """
        return keypair['public']['value']

    def _set_public_key(self, element, proof=None):
        """
        :type element: ModPrimeElement
        :type proof: dict
        :rtype: dict
        """
        public_key = {'value': element, 'proof': proof}
        return public_key

    @abstractmethod
    def deserialize_public_key(self, value, proof=None):
        """
        """

    def _extract_public_key(self, public_key):
        """
        :type public_key: dict
        :rtype: (ModPrimeElement, dict)
        """
        return public_key['value'], public_key['proof']

    def get_key(self, public_key):
        """
        :type public_key: dict or ModPrimeElement
        :rtype: ModPrimeElement
        """
        return public_key['value'] if type(public_key) is dict else public_key

    def get_value(self, public_key):
        """
        :type public_key: dict or ModPrimeElement
        :rtype: int
        """
        value = public_key['value'] if type(public_key) is dict else public_key
        return value.to_int()


class ElGamalCrypto(KeyManager, metaclass=ABCMeta):
    """
    Abstract class for ElGamal cryptosystems
    """

    # Initialization

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

    # System

    @abstractmethod
    def parameters(self):
        """
        JSON
        """

    @abstractmethod
    def _parameters(self):
        """
        """

    @abstractmethod
    def textify_params(self, crypto_params):
        """
        For testing voting
        """

    @abstractmethod
    def check_textified_params(self, t08, t09, t10):
        """
        For testing voting
        """

    @abstractmethod
    def mk_vote_crypto(self, t08, t09, t10):
        """
        Formats appropriately provided texts (tought of as crypto parameters
        extracted from some vote-text), so that they can be compared to the
        present cryptosystem's parameters
        """

    # Deserialization

    @abstractmethod
    def to_exponent(self, integer):
        """
        """

    @abstractmethod
    def to_element(self, element):
        """
        """

    @abstractmethod
    def deserialize_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """
        alpha = self.to_element(alpha)
        beta = self.to_element(beta)
        commitment = self.to_element(commitment)
        challenge = self.to_exponent(challenge)
        response = self.to_exponent(response)

        ciphertext = self.set_ciphertext(alpha, beta)
        proof = self.set_schnorr_proof(commitment, challenge, response)

        encrypted_ballot = self.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot

    @abstractmethod
    def encode_integer(self, integer):
        """
        """

    # Schnorr protocol

    @abstractmethod
    def _schnorr_proof(self, secret, public, *extras):
        """
        """

    @abstractmethod
    def _schnorr_verify(self, proof, public, *extras):
        """
        """
        pass

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
        :type proof: dict
        :rtype: (ModPrimElement, mpz, mpz)
        """
        commitment = proof['commitment']
        challenge = proof['challenge']
        response = proof['response']

        return commitment, challenge, response

    @abstractmethod
    def serialize_scnorr_proof(self, proof):
        """
        """

    @abstractmethod
    def deserialize_schnorr_proof(self, proof):
        """
        """

    # Chaum-Pedersen protocol

    @abstractmethod
    def _chaum_pedersen_proof(self, ddh, z):
        """
        """

    @abstractmethod
    def _chaum_pedersen_verify(self, ddh, proof):
        """
        """

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

    def _extract_chaum_pedersen_proof(self, proof):
        """
        :type proof: dict
        :rtype: (ModPrimElement, ModPrimElement, mpz, mpz)
        """
        base_commitment = proof['base_commitment']
        message_commitment = proof['message_commitment']
        challenge = proof['challenge']
        response = proof['response']

        return base_commitment, message_commitment, challenge, response


    # Digital Signature Algorithm

    @abstractmethod
    def _dsa_signature(self, exponent, private_key):
        """
        """

    @abstractmethod
    def _dsa_verify(self, exponent, signature, public_key):
        """
        """

    def set_dsa_signature(self, exponent, c_1, c_2):
        """
        """
        signature = {
            'exponent': exponent,
            'commitments': {
                'c_1': c_1,
                'c_2': c_2
            }
        }

        return signature

    def _extract_dsa_signature(self, signature):
        """
        :type signature: dict
        :rtype: (mpz, mpz, mpz)
        """
        exponent = signature['exponent']
        commitments = signature['commitments']
        c_1 = commitments['c_1']
        c_2 = commitments['c_2']
        return exponent, c_1, c_2

    @abstractmethod
    def deserialize_dsa_signature(self, signature):
        """
        """

    # Text-message signatures

    @abstractmethod
    def sign_text_message(self, message, private_key):
        """
        """

    @abstractmethod
    def verify_text_signature(self, signed_message, public_key):
        """
        """

    def set_signed_message(self, message, signature):
        """
        :type message: str
        :type signature: dict
        :rtype: dict
        """
        return {'message': message, 'signature': signature}

    def _extract_message_signature(self, signed_message):
        """
        :type signed_message: dict
        :rtype: tuple
        """
        message = signed_message['message']
        signature = signed_message['signature']
        return message, signature


    def extract_signed_message(self, signed_message):
        """
        :type signed_message: dict
        :rtype: tuple
        """
        message = signed_message['message']
        signature = signed_message['signature']
        exponent, c_1, c_2 = self._extract_dsa_signature(signature)
        return message, exponent, c_1, c_2

    # ElGamal encryption and decryption

    @abstractmethod
    def encrypt(self, element, public_key, randomness=None, get_secret=False):
        """
        """

    @abstractmethod
    def _reencrypt(self, ciphertext, public_key, randomness=None, get_secret=False):
        """
        """

    @abstractmethod
    def prove_encryption(self, ciphertext, randomness):
        """
        """

    @abstractmethod
    def verify_encryption(self, ciphertext_proof):
        """
        """

    @abstractmethod
    def _decrypt(self, ciphertext, private_key):
        """
        """

    @abstractmethod
    def _decrypt_with_decryptor(self, ciphertext, decryptor):
        """
        """

    @abstractmethod
    def decrypt_with_randomness(self, ciphertext, public, secret):
        """
        """

    def set_ciphertext(self, alpha, beta):
        """
        :type alpha: ModPrimeElement
        :type beta: ModPrimeElement
        :rtype: dict
        """
        return {'alpha': alpha, 'beta': beta}

    def extract_ciphertext(self, ciphertext):
        """
        :type ciphertext: dict
        :rtype: (ModPrimeElement, ModPrimeElement)
        """
        alpha = ciphertext['alpha']
        beta = ciphertext['beta']
        return alpha, beta

    @abstractmethod
    def serialize_ciphertext(self, ciphertext):
        """
        """

    def set_ciphertext_proof(self, ciphertext, proof):
        """
        :type ciphertext: dict
        :type proof: dict
        :rtype: dict
        """
        return {'ciphertext': ciphertext, 'proof': proof}

    def extract_ciphertext_proof(self, ciphertext_proof):
        """
        Extracts values from a dictionary of the form

        {'ciphertext': dict, 'proof': dict}

        :type ciphertext_proof: dict
        :rtype: (dict, dict)
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
