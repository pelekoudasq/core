import pytest

from mixnets import Zeus_SK, MixnetError
from crypto import WrongCryptoError
from crypto.modprime import ModPrimeElement

ROUNDS = 100
MIXES = 20

from .constants import _4096_SYSTEM, _4096_ELECTION_KEY

def test__MixnetError__at__Zeus_SK__construction():
    with pytest.raises(MixnetError):
        Zeus_SK({'key_1': 0}, 1)

def test__WrongCrypto__at__Zeus_SK__construction():
    class EllipticCrypto(object): pass
    system = EllipticCrypto()
    with pytest.raises(WrongCryptoError):
        Zeus_SK({'cryptosystem': system,
            'nr_rounds': ROUNDS,
            'nr_mixes': MIXES
        }, _4096_ELECTION_KEY)
