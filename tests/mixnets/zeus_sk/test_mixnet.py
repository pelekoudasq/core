import pytest

from copy import deepcopy

from mixnets import Zeus_SK, MixnetError
from mixnets.zeus_sk.mixnet import MixNotVerifiedError
from crypto import WrongCryptoError
from tests.mixnets.zeus_sk.helpers import _make_ciphers_to_mix
from utils.binutils import bit_iterator

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


# Cipher-mix verification

# Success (sync)

__mixnet__ciphers_to_mix__nr_rounds = []

for (mixnet, election_key, nr_rounds) in (
    (RES11_ZEUS_SK, RES11_ELECTION_KEY, 24),
    (_2048_ZEUS_SK, _2048_ELECTION_KEY, 12),
    (_4096_ZEUS_SK, _4096_ELECTION_KEY, 3)
):
    __mixnet__ciphers_to_mix__nr_rounds.append(
        (mixnet, _make_ciphers_to_mix(mixnet, election_key), nr_rounds))

@pytest.mark.parametrize('mixnet, ciphers_to_mix, nr_rounds',
    __mixnet__ciphers_to_mix__nr_rounds)
def test_cipher_mix_verification_success(mixnet, ciphers_to_mix, nr_rounds):
    cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_rounds=nr_rounds, nr_parallel=0)
    assert mixnet.verify_cipher_mix(cipher_mix, nr_parallel=0)

# Failures (sync)

__failure_cases = []

for (mixnet, election_key, nr_rounds) in (
    (RES11_ZEUS_SK, RES11_ELECTION_KEY, 24),
    (_2048_ZEUS_SK, _2048_ELECTION_KEY, 12),
    (_4096_ZEUS_SK, _4096_ELECTION_KEY, 3)
):
    ciphers_to_mix = _make_ciphers_to_mix(mixnet, election_key)
    cipher_mix = mixnet.mix_ciphers(ciphers_to_mix)

    # Corrupt keys
    corrupt = deepcopy(cipher_mix)
    del corrupt['public']
    __failure_cases.append((mixnet, corrupt))

    # Corrupt proof keys
    corrupt = deepcopy(cipher_mix)
    del corrupt['proof']['cipher_collections']
    __failure_cases.append((mixnet, corrupt))

    # Corrupt challenge
    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['challenge'] += '0'
    __failure_cases.append((mixnet, corrupt))

    # Corrupt collections lengths
    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['offset_collections'] += [0]
    __failure_cases.append((mixnet, corrupt))

    # Corrupt first round
    corrupt = deepcopy(cipher_mix)
    bit = next(bit_iterator(int(corrupt['proof']['challenge'], 16)))
    if bit == 0:
        preimages = corrupt['original_ciphers']
        images = corrupt['proof']['cipher_collections'][0]
    else:
        preimages = corrupt['proof']['cipher_collections'][0]
        images = corrupt['mixed_ciphers']
    images[0][0].reduce_value()
    __failure_cases.append((mixnet, corrupt))


@pytest.mark.parametrize('mixnet, cipher_mix', __failure_cases)
def test_cipher_mix_verification_failure(mixnet, cipher_mix):
    with pytest.raises(MixNotVerifiedError):
        mixnet.verify_cipher_mix(cipher_mix, nr_parallel=0)