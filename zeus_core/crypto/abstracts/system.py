from abc import ABCMeta, abstractmethod

class KeyManager(object, metaclass=ABCMeta):
    """
    Key-management interface
    """

    @abstractmethod
    def keygen(self, private_key=None):
        """
        """

    def _set_keypair(self, private_key, public_key):
        """
        """
        keypair = {'private': private_key, 'public': public_key}
        return keypair

    def extract_keypair(self, keypair):
        """
        """
        return keypair['private'], keypair['public']

    def _get_private(self, keypair):
        """
        """
        return keypair['private']

    def _get_public(self, keypair):
        """
        """
        return keypair['public']

    def _get_public_value(self, keypair):
        """
        """
        return keypair['public']['value']

    @abstractmethod
    def validate_public_key(self, public_key):
        """
        """

    def _set_public_key(self, element, proof=None):
        """
        """
        public_key = {'value': element, 'proof': proof}
        return public_key

    @abstractmethod
    def deserialize_public_key(self, value, proof=None):
        """
        """

    def _extract_public_key(self, public_key):
        """
        """
        return public_key['value'], public_key['proof']

    def get_key_value(self, public_key):
        """
        """
        return public_key['value'] \
            if type(public_key) is dict else public_key

    def get_hex_value(self, public_key):
        """
        """
        return self.get_key_value(public_key).to_hex()

    def get_int_value(self, public_key):
        """
        """
        return self.get_key_value(public_key).to_int()

    def get_key_proof(self, public_key):
        """
        """
        return public_key['proof']

    def _combine_public_keys(self, initial, public_keys):
        """
        Assumes provided keys in the form of group elements
        """
        combined = initial
        for public_key in public_keys:
            combined = combined * public_key
        return combined


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
        """

    @abstractmethod
    def hex_parameters(self):
        """
        """

    @abstractmethod
    def hex_labels(self, crypto_params):
        """
        """

    @abstractmethod
    def _parameters(self):
        """
        """

    @abstractmethod
    def check_labels(self, t08, t09, t10):
        """
        """

    @abstractmethod
    def hexify_crypto(self, crypto):
        """
        """

    @abstractmethod
    def unhexify_crypto(self, t08, t09, t10):
        """
        """

    @abstractmethod
    def int_to_exponent(self, integer):
        """
        """

    @abstractmethod
    def hex_to_exponent(self, hex_string):
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

    def deserialize_trustees(self, trustees):
        """
        """
        deserialize_public_key = self.deserialize_public_key
        deserialized = []
        append = deserialized.append
        for trustee in trustees:
            trustee = deserialize_public_key(trustee['value'], trustee['proof'])
            append(trustee)
        return deserialized

    def serialize_encrypted_ballot(self, encrypted_ballot):
        """
        """
        ciphertext, proof = self.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = self.extract_ciphertext(ciphertext)
        commitment, challenge, response = self.extract_schnorr_proof(proof)

        alpha = alpha.to_int()
        beta = beta.to_int()
        commitment = commitment.to_int()
        challenge = int(challenge)
        response = int(response)

        return alpha, beta, commitment, challenge, response


    def deserialize_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """
        alpha = self.int_to_element(alpha)
        beta = self.int_to_element(beta)
        commitment = self.int_to_element(commitment)
        challenge = self.int_to_exponent(challenge)
        response = self.int_to_exponent(response)

        ciphertext = self.set_ciphertext(alpha, beta)
        proof = self.set_schnorr_proof(commitment, challenge, response)

        encrypted_ballot = self.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot

    def unhexify_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """
        alpha = self.hex_to_element(alpha)
        beta = self.hex_to_element(beta)
        commitment = self.hex_to_element(commitment)
        challenge = self.hex_to_exponent(challenge)
        response = self.hex_to_exponent(response)

        ciphertext = self.set_ciphertext(alpha, beta)
        proof = self.set_schnorr_proof(commitment, challenge, response)
        encrypted_ballot = self.set_ciphertext_proof(ciphertext, proof)

        return encrypted_ballot


    @abstractmethod
    def hexify_encrypted_ballot(self, encrypted_ballot):
        """
        """

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
        signature = {}
        signature['exponent'] = exponent
        signature['commitments'] = {'c_1': c_1, 'c_2': c_2}

        return signature

    def _extract_dsa_signature(self, signature):
        """
        """
        exponent = signature['exponent']
        commitments = signature['commitments']
        c_1 = commitments['c_1']
        c_2 = commitments['c_2']
        return exponent, c_1, c_2

    @abstractmethod
    def hexify_dsa_signature(self, signature):
        """
        """

    @abstractmethod
    def unhexify_dsa_signature(self, signature):
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
        """
        return {'message': message, 'signature': signature}

    def _extract_message_signature(self, signed_message):
        """
        """
        message = signed_message['message']
        signature = signed_message['signature']
        return message, signature


    def extract_signed_message(self, signed_message):
        """
        """
        message = signed_message['message']
        signature = signed_message['signature']
        return message, signature

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
        """
        return {'alpha': alpha, 'beta': beta}

    def extract_ciphertext(self, ciphertext):
        """
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
        """
        return {'ciphertext': ciphertext, 'proof': proof}

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
