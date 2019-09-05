from .constants import (_2048_PRIME, _2048_PRIMITIVE, _2048_ORDER, _2048_GENERATOR,
    _4096_PRIME, _4096_PRIMITIVE, _4096_ORDER, _4096_GENERATOR)

from .modprime import ModPrimeCrypto, ModPrimeElement
from .exceptions import WrongCryptoError

def make_crypto(cls, config):
    return cls(*cls._extract_config(config))

__all__ = (

    'make_crypto',

    # cryptosystems and algebra

    'ModPrimeCrypto', 'ModPrimeElement',

    # numerical constants

    '_2048_PRIME', '_2048_PRIMITIVE', '_2048_ORDER', '_2048_GENERATOR',
    '_4096_PRIME', '_4096_PRIMITIVE', '_4096_ORDER', '_4096_GENERATOR',

    # exceptions

    'WrongCryptoError',
)
