import Crypto
from Crypto.Util.number import isPrime

from .elgamal import ElGamalCrypto
from .exceptions import WrongCryptoError, WeakCryptoError
from .algebra import add, mul, divmod, mod, pow, inv
from .utils import bytes_to_int, hash_nums, random_integer


class EllipticCrypto(ElGamalCrypto):


    def __init__(self, *config):
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


    def chaum_pedersen_proof(self, u, v, w, z):
        """
        """
        pass


    def chaum_pedersen_verify(self, u, v, w, proof):
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

    def random_element(self):
        """
        """
        pass


    def fiatshamir(self, *elements):
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
