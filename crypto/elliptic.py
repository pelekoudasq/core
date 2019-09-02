import Crypto

from .elgamal import ElGamalCrypto
from .exceptions import WrongCryptoError, WeakCryptoError
from utils import int_from_bytes, hash_nums, random_integer


class EllipticCrypto(ElGamalCrypto):


    def __init__(self, config, *opts):
        pass

    @property
    def system(self):
        pass


# --------------------------------- Interface ---------------------------------

    def schnorr_proof(self, secret, public, *extras):
        """
        """
        pass


    def schnorr_verify(self, proof, public, *extras):
        """
        """
        pass


    def chaum_pedersen_proof(self, ddh, z):
        """
        """
        pass


    def chaum_pedersen_verify(self, ddh, proof):
        """
        """
        pass


    def keygen(self, private_key=None, schnorr=False):
        """
        """
        pass


    def sign_element(self, element, private_key):
        """
        """
        pass


    def verify_element_signature(self, signature, public_key):
        """
        """
        pass


    def sign_text_message(self, message, private_key):
        """
        """
        pass


    def verify_text_signature(self, signed_message, public_key):
        """
        """
        pass


    def encrypt_element(self, element, public_key, randomness=None):
        """
        """
        pass


# --------------------------------- Internals ---------------------------------

    @property
    def params(self):
        """
        """
        pass


    def _operationsize(self, text_message):
        """
        """
        pass


    def _random_element(self):
        """
        """
        pass


    def _fiatshamir(self, *elements):
        """
        """
        pass


# ------------------------------- Static methods -------------------------------

    @staticmethod
    def generate_system(*config):
        """
        """
        pass


    @classmethod
    def validate_system(cls, system, *options):
        """
        """
        pass
