from .exceptions import WrongCryptoError
from .modprime import ModPrimeCrypto
from .constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE

supported_crypto = (ModPrimeCrypto,)


def mk_cryptosys(crypto_config):
    """
    """
    cls = crypto_config['cls']
    config = crypto_config['config']
    if cls not in supported_crypto:
        err = 'Requested crypto is not supported'
        raise WrongCryptoError(err)
    return cls(*cls._extract_config(config))


def make_2048_SYSTEM():
    return mk_cryptosys({
        'cls': ModPrimeCrypto,
        'config': {
            'modulus': _2048_PRIME,
            'primitive': _2048_PRIMITIVE
        }
    })


def make_4096_SYSTEM():
    return mk_cryptosys({
        'cls': ModPrimeCrypto,
        'config': {
            'modulus': _2048_PRIME,
            'primitive': _2048_PRIMITIVE
        }
    })
