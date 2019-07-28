from .exceptions import (WrongConfigKeysError, WrongCryptoError,
                         WeakCryptoError, UnloadedCryptoError)
from .algebra import (make_cryptosys, validate_cryptosys,
                      make_schnorr_proof, make_schnorr_verify,
                      make_generate_keypair, make_encrypt)


class CryptoController(object):

    def __init__(self, config, _type):

        self.config = config
        self.type = _type

        self.primitives = None


    def load_cryptosystem(self):

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
        generate_keypair = make_generate_keypair(cryptosys)
        encrypt = make_encrypt(cryptosys)

        self.primitives = {
            "cryptosys": cryptosys,
            "schnorr_proof": schnorr_proof,
            "schnorr_verify": schnorr_verify,
            "generate_keypair": generate_keypair,
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
