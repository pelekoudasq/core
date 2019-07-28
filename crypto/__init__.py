from .exceptions import WrongConfigKeysError, WrongCryptoError, WeakCryptoError, UnloadedCryptoError
from .algebra import make_cryptosys, validate_cryptosys, make_operations, make_hash_func, make_generate_keypair, make_encrypt

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

        self.primitives = {
            "cryptosys": cryptosys,
            "operations": make_operations(cryptosys),
            "hash_func": make_hash_func(cryptosys),
            "generate_keypair": make_generate_keypair(cryptosys),
            "encrypt": make_encrypt(cryptosys),
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
