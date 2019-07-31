from abc import ABCMeta, abstractmethod
from .exceptions import WrongCryptoError, WeakCryptoError


class ElGamalCrypto(object, metaclass=ABCMeta):

    @abstractmethod
    def __init__(self, cls, config, *opts):
        try:
            system = cls.generate_system(config)
        except WrongCryptoError:
            raise

        try:
            cls.validate_system(system, *opts)
        except (WrongCryptoError, WeakCryptoError):
            raise

        self._set_params(system)


    @abstractmethod
    def _set_params(self, system):
        """
        """

    @staticmethod
    @abstractmethod
    def generate_system(*config):
        """
        """

    @classmethod
    @abstractmethod
    def validate_system(cls, system, *options):
        """
        """


# --------------------------------- Interface ---------------------------------

    @property
    @abstractmethod
    def system():
        """
        """

    @abstractmethod
    def schnorr_proof(self, secret, public, *extras):
        """
        """

    @abstractmethod
    def schnorr_verify(self, proof, public, *extras):
        """
        """

    @abstractmethod
    def chaum_pedersen_proof(self, ddh, z):
        """
        """

    @abstractmethod
    def chaum_pedersen_verify(self, ddh, proof):
        """
        """

    @abstractmethod
    def keygen(self, private_key=None, schnorr=False):
        """
        """

    @abstractmethod
    def sign_element(self, element, private_key):
        """
        """

    @abstractmethod
    def verify_element_signature(self, signature, public_key):
        """
        """

    @abstractmethod
    def sign_text_message(self, message, private_key):
        """
        """

    @abstractmethod
    def verify_text_signature(self, signed_message, public_key):
        """
        """

    @abstractmethod
    def encrypt_element(self, element, public_key, randomness=None):
        """
        """
        pass

# --------------------------------- Internals ---------------------------------

    @property
    @abstractmethod
    def _params(self):
        """
        """

    # TODO: Include algebraic (group) operations?

    @abstractmethod
    def _random_exponent(self):
        """
        """

    @abstractmethod
    def _random_element(self):
        """
        """

    @abstractmethod
    def _algebraize(self, text_message):
        """
        """
        pass

    @abstractmethod
    def _fiatshamir(self, *elements):
        """
        """
