from abc import ABCMeta, abstractmethod


class ElGamalCrypto(object, metaclass=ABCMeta):
    """
    Abstract class for ElGamal cryptosystems
    """

    # ------------------------------- Primitives -------------------------------

    # Key management

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

    def _extract_keypair(self, keypair):
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
    def _set_public_key_from_value(self, value, proof=None):
        """
        """

    def _extract_public_key(self, public_key):
        """
        :type public_key: dict
        :rtype: (ModPrimeElement, dict)
        """
        return public_key['value'], public_key['proof']

    def _get_value(self, public_key):
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
        return value.to_integer()

    # Text-message signatures

    @abstractmethod
    def sign_text_message(self, message, private_key):
        """
        """

    @abstractmethod
    def verify_text_signature(self, signed_message, public_key):
        """
        """

    def _set_signed_message(self, message, signature):
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


    def _extract_signed_message(self, signed_message):
        """
        :type signed_message: dict
        :rtype: tuple
        """
        message = signed_message['message']
        signature = signed_message['signature']
        exponent, c_1, c_2 = self._extract_dsa_signature(signature)
        return message, exponent, c_1, c_2

    # Digital Signature Algorithm

    @abstractmethod
    def _dsa_signature(self, exponent, private_key):
        """
        """

    @abstractmethod
    def _dsa_verify(self, exponent, signature, public_key):
        """
        """

    def _set_dsa_signature(self, exponent, c_1, c_2):
        """
        :exponent: mpz
        :type c_1: mpz
        :type c_2: mpz
        :rtype: dict
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
        :rtype: tuple
        """
        exponent = signature['exponent']
        commitments = signature['commitments']
        c_1 = commitments['c_1']
        c_2 = commitments['c_2']
        return exponent, c_1, c_2
