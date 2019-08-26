import pytest

from mixnets import Zeus_SK, MixnetError
from crypto import WrongCryptoError

ROUNDS = 100
MIXES = 20

from tests.constants import (RES11_ELECTION_KEY, _2048_ELECTION_KEY,
    _4096_ELECTION_KEY, RES11_ZEUS_SK, _4096_ZEUS_SK, _2048_ZEUS_SK)


# Test construction errors

def test__MixnetError__at__Zeus_SK__construction():
    with pytest.raises(MixnetError):
        Zeus_SK({'key_1': 0}, 1)

def test__WrongCryptoError__at__Zeus_SK__construction():
    class EllipticCrypto(object): pass
    system = EllipticCrypto()
    with pytest.raises(WrongCryptoError):
        Zeus_SK({'cryptosystem': system,
            'nr_rounds': ROUNDS,
            'nr_mixes': MIXES
        }, _4096_ELECTION_KEY)


# Test crypto

__mixnet__alpha__beta__public__randomness = []

for (mixnet, public) in (
        (RES11_ZEUS_SK, RES11_ELECTION_KEY),
        (_2048_ZEUS_SK, _2048_ELECTION_KEY),
        (_4096_ZEUS_SK, _4096_ELECTION_KEY)):
    group = mixnet.cryptosystem.group

    alpha = group.random_element()
    beta = group.random_element()
    randomness = group.random_exponent(min=3)

    __mixnet__alpha__beta__public__randomness.append(
        (mixnet, alpha, beta, public, randomness))


@pytest.mark.parametrize('mixnet, alpha, beta, public, randomness',
    __mixnet__alpha__beta__public__randomness)
def test__reencrypt(mixnet, alpha, beta, public, randomness):

    system = mixnet.cryptosystem

    ciphertext = system._reencrypt(ciphertext={
        'alpha': alpha,
        'beta': beta
    }, public_key=public, randomness=randomness, get_secret=False)

    alpha, beta = mixnet._reencrypt(alpha, beta, public, randomness=randomness)

    assert alpha, beta == system._extract_ciphertext(alpha, beta)


# Test formats

__mixnet__cipher_collection__result = [
    (
        RES11_ZEUS_SK,
        {
            'original_ciphers': [{'alpha': 0, 'beta': 1}, {'alpha': 2, 'beta': 3}]
        },
        {
            'modulus': RES11_ZEUS_SK.cryptosystem.group.modulus,
            'order': RES11_ZEUS_SK.cryptosystem.group.order,
            'generator': RES11_ZEUS_SK.cryptosystem.group.generator.value,
            'public': RES11_ELECTION_KEY,
            'original_ciphers': [(0, 1), (2, 3)],
            'mixed_ciphers': [(0, 1), (2, 3)]
        }
    ),
    (
        _4096_ZEUS_SK,
        {
            'original_ciphers': [{'alpha': 4, 'beta': 5}, {'alpha': 6, 'beta': 7}],
            'mixed_ciphers': [{'alpha': 0, 'beta': 1}, {'alpha': 2, 'beta': 3}]
        },
        {
            'modulus': _4096_ZEUS_SK.cryptosystem.group.modulus,
            'order': _4096_ZEUS_SK.cryptosystem.group.order,
            'generator': _4096_ZEUS_SK.cryptosystem.group.generator.value,
            'public': _4096_ELECTION_KEY,
            'original_ciphers': [(4, 5), (6, 7)],
            'mixed_ciphers': [(0, 1), (2, 3)]
        }
    ),
    (
        _2048_ZEUS_SK,
        {
            'original_ciphers': [{'alpha': 8, 'beta': 9}, {'alpha': 0, 'beta': 1}],
            'proof': 666
        },
        {
            'modulus': _2048_ZEUS_SK.cryptosystem.group.modulus,
            'order': _2048_ZEUS_SK.cryptosystem.group.order,
            'generator': _2048_ZEUS_SK.cryptosystem.group.generator.value,
            'public': _2048_ELECTION_KEY,
            'original_ciphers': [(8, 9), (0, 1)],
            'mixed_ciphers': [(8, 9), (0, 1)],
            'proof': 666
        }
    ),
]

@pytest.mark.parametrize('mixnet, cipher_collection, result',
    __mixnet__cipher_collection__result)
def test__prepare_mix(mixnet, cipher_collection, result):
    assert result == mixnet._prepare_mix(cipher_collection)


__mixnet__mixed_collection__result = [
    (
        RES11_ZEUS_SK,
        {
            'original_ciphers': [(0, 1), (2, 3)],
            'mixed_ciphers': [(4, 5), (6, 7)],
            'proof': 666
        },
        {
            'modulus': RES11_ZEUS_SK.cryptosystem.group.modulus,
            'order': RES11_ZEUS_SK.cryptosystem.group.order,
            'generator': RES11_ZEUS_SK.cryptosystem.group.generator.value,
            'public': RES11_ELECTION_KEY,
            'original_ciphers': [{'alpha': 0, 'beta': 1}, {'alpha': 2, 'beta': 3}],
            'mixed_ciphers': [{'alpha': 4, 'beta': 5}, {'alpha': 6, 'beta': 7}],
            'proof': 666
        }
    ),
]

@pytest.mark.parametrize('mixnet, mixed_collection, result',
    __mixnet__mixed_collection__result)
def test__extract_mix(mixnet, mixed_collection, result):
    assert result == mixnet._extract_mix(mixed_collection)
