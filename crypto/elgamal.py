from abc import ABCMeta, abstractmethod


class ElGamalCrypto(object, metaclass=ABCMeta):

    __slots__ = (
        '__system',
        '__schnorr_proof',
        '__schnorr_verify',
        '__chaum_pedersen_proof',
        '__chaum_pedersen_verify',
        '__keygen'
    )


    def __init__(self, *config):
        """
        """
        try:
            system = ElGamalCrypto.generate_system(*config)
        except WrongCryptoError:
            raise

        try:
            ElGamalCrypto.validate_system(system)
        except (WrongCryptoError, WeakCryptoError):
            raise

        self.__system = system
        ElGamalCrypto.load_primitives(system)


    @staticmethod
    def load_primitives(system):
        """
        """
        ElGamalCrypto.make_schnorr_proof(system)
        ElGamalCrypto.make_schnorr_verify(system)
        ElGamalCrypto.make_chaum_pedersen_proof(system)
        ElGamalCrypto.make_chaum_pedersen_verify(system)
        ElGamalCrypto.make_keygen(system)

    @property
    def system():
        return self.__system


# --------------------------------- Interface ---------------------------------

    # def schnorr_proof(self, secret, public, *extras):
    #     """
    #     """
    #     return self.__schnorr_proof(self, secret, public, *extras)
    #
    #
    # def schnorr_verify(self, proof, public, *extras):
    #     """
    #     """
    #     return self.__schnorr_verify(self, proof, public, *extras)
    #
    #
    # def chaum_pedersen_proof(u, v, w, z):
    #     """
    #     """
    #     return self.__chaum_pedersen_proof(u, v, w, z)
    #
    #
    # def chaum_pedersen_verify(u, v, w, proof):
    #     """
    #     """
    #     return self.__chaum_pedersen_verify(u, v, w, proof)
    #
    #
    # def keygen(private_key=None, schnorr=False):
    #     """
    #     """
    #     return self.__keygen(private_key, schnorr)


# ------------------------------ Abstract methods ------------------------------

    @staticmethod
    @abstractmethod
    def generate_system(*config):
        """
        """

    @staticmethod
    @abstractmethod
    def extract_parameters(system):
        """
        """

    @staticmethod
    @abstractmethod
    def validate_system(system):
        """
        """

    @staticmethod
    @abstractmethod
    def make_schnorr_proof(system):
        """
        """

    @staticmethod
    @abstractmethod
    def make_schnorr_verify(system):
        """
        """

    @staticmethod
    @abstractmethod
    def make_chaum_pedersen_proof(system):
        """
        """

    @staticmethod
    @abstractmethod
    def make_chaum_pedersen_proof(system):
        """
        """

    @staticmethod
    @abstractmethod
    def make_keygen(system):
        """
        """
