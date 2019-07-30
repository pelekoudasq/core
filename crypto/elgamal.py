from abc import ABCMeta, abstractmethod, abstractproperty


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
    def encrypt_element(self, element, public_key, randomness=None):
        """
        """
        pass

# --------------------------------- Internals ---------------------------------

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

    @staticmethod
    @abstractmethod
    def validate_system(system):
        """
        """
