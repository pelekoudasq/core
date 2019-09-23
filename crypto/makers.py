from .exceptions import WrongCryptoError
from .modprime import ModPrimeCrypto
from .constants import _2048_PRIME, _2048_ORDER, _4096_PRIME, _4096_ORDER

supported_crypto = (ModPrimeCrypto,)

def make_crypto(cls, config):
    if cls not in supported_crypto:
        raise WrongCryptoError('Requested crypto is not supported')
    return cls(*cls._extract_config(config))

def make_2048_SYSTEM():
    return make_crypto(ModPrimeCrypto, {
        'modulus': _2048_PRIME,
        'primitive': _2048_PRIMITIVE
    })

def make_4096_SYSTEM():
    return make_crypto(ModPrimeCrypto, {
        'modulus': _4096_PRIME,
        'primitive': _4096_PRIMITIVE
    })
