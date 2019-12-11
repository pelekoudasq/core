import pytest
from copy import deepcopy

from zeus_core.mixnets import Zeus_SK
from zeus_core.mixnets.exceptions import WrongMixnetError, MixNotVerifiedError
from zeus_core.utils import bit_iterator

from tests.constants import (RES11_ELECTION_KEY, _2048_ELECTION_KEY,
    _4096_ELECTION_KEY, RES11_ZEUS_SK, _4096_ZEUS_SK, _2048_ZEUS_SK)
from tests.mixnets.utils import mk_cipher_mix
from zeus_core.utils.random import random_integer


ROUNDS = 100
MIXES = 20


# Test construction errors

def test_WrongMixnetError_with_invalid_params():
    with pytest.raises(WrongMixnetError):
        Zeus_SK({'key_1': 0}, 1)

def test_WrongMixnetError_with_unsupported_crypto_type():
    class EllipticCrypto(object): pass
    with pytest.raises(WrongMixnetError):
        Zeus_SK({'cryptosys': EllipticCrypto(),
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
    group = mixnet.group

    alpha = group.random_element()
    beta = group.random_element()
    randomness = group.random_exponent(min=3)

    __mixnet__alpha__beta__public__randomness.append(
        (mixnet, alpha, beta, public, randomness))


@pytest.mark.parametrize('mixnet, alpha, beta, public, randomness',
    __mixnet__alpha__beta__public__randomness)
def test_reencrypt(mixnet, alpha, beta, public, randomness):

    system = mixnet.cryptosys

    ciphertext = system.reencrypt(ciphertext={
        'alpha': alpha,
        'beta': beta
    }, public_key=public, randomness=randomness, get_secret=False)

    alpha, beta = mixnet.reencrypt(alpha, beta, public, randomness=randomness)

    assert alpha, beta == system.extract_ciphertext(alpha, beta)


# Cipher-mix verification success

__mixnet__ciphers_to_mix = []

for (mixnet, election_key) in (
    # (RES11_ZEUS_SK, RES11_ELECTION_KEY),
    (_2048_ZEUS_SK, _2048_ELECTION_KEY),
    # (_4096_ZEUS_SK, _4096_ELECTION_KEY),
):
    __mixnet__ciphers_to_mix.append(
        (mixnet, mk_cipher_mix(mixnet, election_key)))

@pytest.mark.parametrize('mixnet, ciphers_to_mix',
    __mixnet__ciphers_to_mix)
def test_cipher_mix_verification_success(mixnet, ciphers_to_mix):
    cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_parallel=0)
    assert mixnet.verify_mix(cipher_mix, nr_parallel=0)


# Cipher-mix verification failures

__failure_cases = []

for (mixnet, election_key) in (
    (_2048_ZEUS_SK, _2048_ELECTION_KEY),
    # (_4096_ZEUS_SK, _4096_ELECTION_KEY)
):
    ciphers_to_mix = mk_cipher_mix(mixnet, election_key)
    cipher_mix = mixnet.mix_ciphers(ciphers_to_mix)

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
        mixnet.verify_mix(cipher_mix, nr_parallel=0)


# Challenge computation

def test_compute_mix_challenge():
    mixnet = _2048_ZEUS_SK
    public = _2048_ELECTION_KEY

    parameters = mixnet.cryptosys.hex_parameters()
    group = mixnet.group

    modulus = parameters['modulus']
    order = parameters['order']
    generator = parameters['generator']

    nr_ciphers = random_integer(2, 10)
    nr_collections = random_integer(2, 7)
    random_element = group.random_element

    original_ciphers = [(random_element(), random_element())
        for _ in range(nr_ciphers)]
    mixed_ciphers = [(random_element(), random_element())
        for _ in range(nr_ciphers)]
    cipher_collections = [[(random_element(), random_element())
        for _ in range(nr_ciphers)] for _ in range(nr_collections)]

    cipher_mix = {
        'header': {
            'modulus': modulus,
            'order': order,
            'generator': generator,
            'public': public.to_hex(),
        },
        'original_ciphers': original_ciphers,
        'mixed_ciphers': mixed_ciphers,
        'proof': {
            'cipher_collections': cipher_collections
        }
    }
