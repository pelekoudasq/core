from abc import ABCMeta, abstractmethod


class ElGamalCrypto(object, metaclass=ABCMeta):

    @property
    @abstractmethod
    def system():
        """
        """

# --------------------------------- Interface ---------------------------------

    @abstractmethod
    def schnorr_proof(self, secret, public, *extras):
        """
        """

    @abstractmethod
    def schnorr_verify(self, proof, public, *extras):
        """
        """

    @abstractmethod
    def chaum_pedersen_proof(u, v, w, z):
        """
        """

    @abstractmethod
    def chaum_pedersen_verify(u, v, w, proof):
        """
        """

    @abstractmethod
    def keygen(private_key=None, schnorr=False):
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
    def params(self):
        """
        """

    @abstractmethod
    def algebraize(self, text_message):
        """
        """
        pass

    @abstractmethod
    def random_element(self):
        """
        """

    @abstractmethod
    def fiatshamir(self, *elements):
        """
        """

# ------------------------------- Static methods -------------------------------

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
