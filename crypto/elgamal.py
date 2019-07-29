from abc import ABCMeta, abstractmethod


class ElGamalCrypto(metaclass=ABCMeta):

    @abstractmethod
    def __init__(self, *config):
        """
        """
        try:
            ElGamalCrypto.validate_config(*config)
        except: # Put here exceptions
            raise

        system = generate_system(*config)

        try:
            ElGamalCrypto.validate_system(system)
        except: # Put here exceptions
            raise

        self.__system = system
        ElGamalCrypto.load_primitives(system)

    @staticmethod
    @abstractmethod
    def validate_config():
        """
        """

    @staticmethod
    @abstractmethod
    def generate_system():
        """
        """

    @staticmethod
    @abstractmethod
    def validate_system():
        """
        """

    @property
    def system():
        return self.__system

    @staticmethod
    @abstractmethod
    def load_primitives(system):
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
    def chaum_pedersen_proof(u, v, w, z):
        """
        """


    @abstractmethod
    def chaum_pedersen_verify(u, v, w, proof):
        """
        """


    # @abstractmethod
    # def keygen(private_key=None, schnorr=False):
    #     """
    #     """
    #
    # @abstractmethod
    # def validate_key(public_key, proof):
    #     """
    #     """
    #     pass
    #
    # @abstractmethod
    # def sign_element():
    #     """
    #     """
    #     pass
    #
    # @abstractmethod
    # def verify_element_signature():
    #     """
    #     """
    #     pass
    #
    # @abstractmethod
    # def sign_message():
    #     """
    #     """
    #
    # @abstractmethod
    # def verify_message_signature():
    #     """
    #     """
    #
    # @abstractmethod
    # def encrypt(element, public_key, randomness=None):
    #     """
    #    """
