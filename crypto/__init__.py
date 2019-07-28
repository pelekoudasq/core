from .exceptions import WrongConfigKeysError, WrongCryptoError, WeakCryptoError, UnloadedCryptoError
from .algebra import make_cryptosys, validate_cryptosys, make_operations, make_hash_func, make_generate_keypair, make_encrypt

class CryptoController(object):

    def __init__(self, config, _type):

        self.config = config
        self.type  = _type

        self.cryptosys  = None
        self.operations = None
        self.hash_func  = None
        self.generate_keypair = None
        self.encrypt    = None

    def load_cryptosystem(self):

        try:
            cryptosys = make_cryptosys(self.config, self.type)
        except (WrongConfigKeysError, WrongCryptoError):
            raise

        # try:
        #     validate_cryptosys(cryptosys)
        # except (WrongCryptoError, WeakCryptoError):
        #     raise

        self.cryptosys  = cryptosys
        self.operations = make_operations(self.cryptosys)
        self.hash_func  = make_hash_func(self.cryptosys)
        self.generate_keypair = make_generate_keypair(self.cryptosys)
        self.encrypt    = make_encrypt(self.cryptosys)

    def reload_cryptosystem(self, config, _type):
        self.__init__(config, _type)
        self.load_cryptosystem()

    def export_primitives(self):

        primitives = self.__dict__

        if None in primitives.values():
            e = 'No Cryptosystem has been loaded'
            raise UnloadedCryptoError(e)

        return primitives
