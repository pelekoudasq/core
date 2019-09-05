from .modprime import ModPrimeCrypto

# ----------------
from .exceptions import WrongCryptoError

supported_crypto = (ModPrimeCrypto,)

def make_crypto(cls, config):
    if cls not in supported_crypto:
        raise WrongCryptoError('Requested crypto is not supported')
    return cls(*cls._extract_config(config))

__all__ = ('make_crypto', 'ModPrimeCrypto',)
