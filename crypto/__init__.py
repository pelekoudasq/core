from .exceptions import (WrongConfigsError, WrongCryptoError, WeakCryptoError,
                         UnloadedCryptoError)
from .algebra import (make_cryptosys, validate_cryptosys,
                      make_schnorr_proof, make_schnorr_verify,
                      make_keygen, make_encrypt)

from abc import ABCMeta, abstractmethod


class CryptoSystem(metaclass=ABCMeta):

    @abstractmethod
    def __init__(self, config):
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
    def chaum_pedersen_proof():
        """
        """

    @abstractmethod
    def chaum_pedersen_verify():
        """
        """

    @abstractmethod
    def keygen(private_key=None, schnorr=False):
        """
        """

    @abstractmethod
    def validate_key(public_key, proof):
        """
        """
        pass

    @abstractmethod
    def sign_element():
        """
        """
        pass

    @abstractmethod
    def verify_element_signature():
        """
        """
        pass

    @abstractmethod
    def sign_message():
        """
        """

    @abstractmethod
    def verify_message_signature():
        """
        """

    @abstractmethod
    def encrypt(element, public_key, randomness=None):
        """
        """



class CryptoController(object):

    def __init__(self, config, _type):

        self.config = config
        self.type = _type

        self.primitives = None


    def load(self):

        try:
            cryptosys = make_cryptosys(self.config, self.type)
        except (WrongConfigKeysError, WrongCryptoError):
            raise

        try:
            validate_cryptosys(cryptosys)
        except (WrongCryptoError, WeakCryptoError):
            raise

        # Make primitives

        schnorr_proof = make_schnorr_proof(cryptosys)
        schnorr_verify = make_schnorr_verify(cryptosys)
        keygen = make_keygen(cryptosys)
        encrypt = make_encrypt(cryptosys)

        self.primitives = {
            "cryptosys": cryptosys,
            "schnorr_proof": schnorr_proof,
            "schnorr_verify": schnorr_verify,
            "keygen": keygen,
            "encrypt": encrypt,
        }


    def reload_cryptosystem(self, config, _type):
        self.__init__(config, _type)
        try:
            self.load_cryptosystem()
        except (WrongCryptoError, WeakCryptoError):
            raise


    def export_primitives(self):

        primitives = self.primitives

        if self.primitives is None:
            e = 'No Cryptosystem has been loaded'
            raise UnloadedCryptoError(e)

        return primitives
