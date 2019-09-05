import pytest
from hashlib import sha256
from itertools import chain

from crypto.modprime import ModPrimeElement
from mixnets.zeus_sk.utils import (compute_mix_challenge, shuffle_ciphers,
    verify_mix_round)
from mixnets.exceptions import RoundNotVerifiedError
from utils.random import random_integer, random_permutation

from tests.constants import (RES11_ZEUS_SK, RES11_ELECTION_KEY,
    _2048_ZEUS_SK, _2048_ELECTION_KEY, _4096_ZEUS_SK, _4096_ELECTION_KEY)

def test_compute_mix_challenge():
    mixnet = RES11_ZEUS_SK
    public = RES11_ELECTION_KEY

    parameters = mixnet.cryptosystem.parameters()
    group = mixnet.cryptosystem.group

    modulus = parameters['modulus']
    order = parameters['order']
    generator = parameters['generator']

    nr_ciphers = random_integer(2, 10)
    nr_collections = random_integer(2, 7)
    random_element = group.random_element

    original_ciphers = [(random_element(), random_element()) for _ in range(nr_ciphers)]
    mixed_ciphers = [(random_element(), random_element()) for _ in range(nr_ciphers)]
    cipher_collections = [[(random_element(), random_element()) for _ in range(nr_ciphers)]
        for _ in range(nr_collections)]

    cipher_mix = {
        'modulus': modulus,
        'order': order,
        'generator': generator,
        'public': public,
        'original_ciphers': original_ciphers,
        'mixed_ciphers': mixed_ciphers,
        'proof': {
            'cipher_collections': cipher_collections
        }
    }

    assert compute_mix_challenge(cipher_mix) == \
        sha256(bytes('%x%x%x%x%s%s%s' % (modulus, order, generator, public.to_integer(),
                    ''.join('%x%x' % (c[0].to_integer(), c[1].to_integer())
                        for c in original_ciphers),
                    ''.join('%x%x' % (c[0].to_integer(), c[1].to_integer())
                        for c in mixed_ciphers),
                    ''.join('%x%x' % (c[0].to_integer(), c[1].to_integer())
                        for c in chain(*cipher_collections))),
                encoding='utf-8')).hexdigest()


__mix_round_verification_parameters = []

nr_ciphers = 12
_range = range(nr_ciphers)

for mixnet, election_key in (
    # (RES11_ZEUS_SK, RES11_ELECTION_KEY),
    (_2048_ZEUS_SK, _2048_ELECTION_KEY),
    (_4096_ZEUS_SK, _4096_ELECTION_KEY)
):
    encrypt_func = mixnet._reencrypt
    public = election_key

    group = mixnet.cryptosystem.group
    modulus = group.modulus
    random_exponent = group.random_exponent
    random_element = group.random_element

    offsets = random_permutation(nr_ciphers)
    randoms = [random_exponent() for _ in _range]

    for bit in (0, 1):
        for verified in (True, False):
            offsets = random_permutation(nr_ciphers)
            randoms = [random_exponent() for _ in _range]

            preimages = [(random_element(), random_element()) for _ in _range]
            if verified:
                images = [None] * nr_ciphers
                for j in _range:
                    preimage = preimages[j]
                    random = randoms[j]
                    offset = offsets[j]
                    image = encrypt_func(preimage[0], preimage[1], public, randomness=random)
                    images[offset] = image
            else:
                images = [(random_element(), random_element()) for _ in _range]

            if bit == 0:
                original_ciphers = preimages
                mixed_ciphers = ['Should play no role in this case...']
                ciphers = images
            else:
                original_ciphers = ['Should play no role in this case...']
                mixed_ciphers = images
                ciphers = preimages

            __mix_round_verification_parameters.append((bit, original_ciphers,
                mixed_ciphers, ciphers, offsets, randoms, encrypt_func, public, verified))



@pytest.mark.parametrize('bit, original_ciphers, mixed_ciphers, ciphers, \
    offsets, randoms, encrypt_func, public, verified',
    __mix_round_verification_parameters)
def test_verify_mix_round(bit, original_ciphers, mixed_ciphers, ciphers,
        offsets, randoms, encrypt_func, public, verified):
    if verified:
        assert verify_mix_round(0, bit, original_ciphers, mixed_ciphers,
            ciphers, offsets, randoms, encrypt_func, public)
    else:
        with pytest.raises(RoundNotVerifiedError):
            verify_mix_round(0, bit, original_ciphers, mixed_ciphers,
                ciphers, offsets, randoms, encrypt_func, public)

def test_AssertionError__at_verify_mix_round():
    with pytest.raises(AssertionError):
        verify_mix_round(0, 2, [], [], [], [], [], None, None)
