"""
"""

from .exceptions import WrongCryptoError
from .modprime import ModPrimeCrypto

supported_crypto = (ModPrimeCrypto,)


def mk_cryptosys(crypto_config):
    """
    """
    cls = crypto_config['cls']
    config = crypto_config['config']
    if cls not in supported_crypto:
        err = "Requested crypto is not supported"
        raise WrongCryptoError(err)
    return cls(*cls._extract_config(config))
