import pytest
from copy import deepcopy

from mixnets import Zeus_sk
from mixnets.exceptions import MixnetError, MixNotVerifiedError
from utils.binutils import bit_iterator

from tests.constants import (RES11_ELECTION_KEY, _2048_ELECTION_KEY,
    _4096_ELECTION_KEY, RES11_ZEUS_SK, _4096_ZEUS_SK, _2048_ZEUS_SK)
from tests.helpers import _make_ciphers_to_mix


ROUNDS = 100
MIXES = 20


# Test construction errors

def test_MixnetError_with_invalid_params():
    with pytest.raises(MixnetError):
        Zeus_sk({'key_1': 0}, 1)

def test_MixnetError_with_unsupported_crypto_type():
    class EllipticCrypto(object): pass
    system = EllipticCrypto()
    with pytest.raises(MixnetError):
        Zeus_sk({'cryptosys': system,
            'nr_rounds': ROUNDS,
            'nr_mixes': MIXES
        }, _4096_ELECTION_KEY)


# Test crypto

__mixnet__alpha__beta__public__randomness = []

for (mixnet, public) in (
        (RES11_ZEUS_SK, RES11_ELECTION_KEY),
        (_2048_ZEUS_SK, _2048_ELECTION_KEY),
        (_4096_ZEUS_SK, _4096_ELECTION_KEY),
    ):
    group = mixnet.cryptosys.group

    alpha = group.random_element()
    beta = group.random_element()
    randomness = group.random_exponent(min=3)

    __mixnet__alpha__beta__public__randomness.append(
        (mixnet, alpha, beta, public, randomness))


@pytest.mark.parametrize('mixnet, alpha, beta, public, randomness',
    __mixnet__alpha__beta__public__randomness)
def test__reencrypt(mixnet, alpha, beta, public, randomness):

    system = mixnet.cryptosys

    ciphertext = system._reencrypt(ciphertext={
        'alpha': alpha,
        'beta': beta
    }, public_key=public, randomness=randomness, get_secret=False)

    alpha, beta = mixnet._reencrypt(alpha, beta, public, randomness=randomness)

    assert alpha, beta == system.extract_ciphertext(alpha, beta)


# Test formats

__mixnet__cipher_collection__result = [
    (
        RES11_ZEUS_SK,
        {
            'original_ciphers': [{'alpha': 0, 'beta': 1}, {'alpha': 2, 'beta': 3}]
        },
        {
            'modulus': RES11_ZEUS_SK.cryptosys.group.modulus,
            'order': RES11_ZEUS_SK.cryptosys.group.order,
            'generator': RES11_ZEUS_SK.cryptosys.group.generator.value,
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
            'modulus': _4096_ZEUS_SK.cryptosys.group.modulus,
            'order': _4096_ZEUS_SK.cryptosys.group.order,
            'generator': _4096_ZEUS_SK.cryptosys.group.generator.value,
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
            'modulus': _2048_ZEUS_SK.cryptosys.group.modulus,
            'order': _2048_ZEUS_SK.cryptosys.group.order,
            'generator': _2048_ZEUS_SK.cryptosys.group.generator.value,
            'public': _2048_ELECTION_KEY,
            'original_ciphers': [(8, 9), (0, 1)],
            'mixed_ciphers': [(8, 9), (0, 1)],
            'proof': 666
        }
    ),
]

@pytest.mark.parametrize('mixnet, cipher_collection, result',
    __mixnet__cipher_collection__result)
def test__set_cipher_mix(mixnet, cipher_collection, result):
    assert result == mixnet._set_cipher_mix(cipher_collection)


__mixnet__mixed_collection__result = [
    (
        RES11_ZEUS_SK,
        {
            'original_ciphers': [(0, 1), (2, 3)],
            'mixed_ciphers': [(4, 5), (6, 7)],
            'proof': 666
        },
        {
            'modulus': RES11_ZEUS_SK.cryptosys.group.modulus,
            'order': RES11_ZEUS_SK.cryptosys.group.order,
            'generator': RES11_ZEUS_SK.cryptosys.group.generator.value,
            'public': RES11_ELECTION_KEY,
            'original_ciphers': [{'alpha': 0, 'beta': 1}, {'alpha': 2, 'beta': 3}],
            'mixed_ciphers': [{'alpha': 4, 'beta': 5}, {'alpha': 6, 'beta': 7}],
            'proof': 666
        }
    ),
]

@pytest.mark.parametrize('mixnet, mixed_collection, result',
    __mixnet__mixed_collection__result)
def test__extract_cipher_mix(mixnet, mixed_collection, result):
    assert result == mixnet._extract_cipher_mix(mixed_collection)


# Cipher-mix verification

# Success (sync)

__mixnet__ciphers_to_mix = []

for (mixnet, election_key) in (
    # (RES11_ZEUS_SK, RES11_ELECTION_KEY),
    (_2048_ZEUS_SK, _2048_ELECTION_KEY),
    # (_4096_ZEUS_SK, _4096_ELECTION_KEY),
):
    __mixnet__ciphers_to_mix.append(
        (mixnet, _make_ciphers_to_mix(mixnet, election_key)))

@pytest.mark.parametrize('mixnet, ciphers_to_mix',
    __mixnet__ciphers_to_mix)
def test_cipher_mix_verification_success(mixnet, ciphers_to_mix):
    cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_parallel=0)
    assert mixnet.verify_cipher_mix(cipher_mix, nr_parallel=0)

# Failures (sync)

__failure_cases = []

for (mixnet, election_key) in (
    (_2048_ZEUS_SK, _2048_ELECTION_KEY),
    # (_4096_ZEUS_SK, _4096_ELECTION_KEY)
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
