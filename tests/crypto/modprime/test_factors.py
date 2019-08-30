import pytest
from functools import reduce
from gmpy2 import mpz

from crypto.exceptions import InvalidFactorsError
from utils import random_integer

from tests.constants import (RES11_SYSTEM, RES11_KEY,
    _2048_SYSTEM, _2048_KEY,
    _4096_SYSTEM, _4096_KEY)


# Factor combination

__system__factors_collections__elems__nr_trustees__nr_factors = []

for system in (RES11_SYSTEM, _2048_SYSTEM, _4096_SYSTEM):
    group = system.group
    for nr_trustees in range(0, 5):
        for nr_factors in range(0, 5):
            elems = [[group.random_element() for j in range(nr_factors)] for i in range(nr_trustees)]
            factors_collections = [[{'data': elems[i][j].value, 'proof': {}} for j in range(nr_factors)] for i in range(nr_trustees)]
            __system__factors_collections__elems__nr_trustees__nr_factors.append((system, factors_collections, elems, nr_trustees, nr_factors))

@pytest.mark.parametrize('system, factors_collections, elems, nr_trustees, nr_factors',
    __system__factors_collections__elems__nr_trustees__nr_factors)
def test__combine_decryption_factors(system, factors_collections, elems, nr_trustees, nr_factors):
    if not nr_trustees or not nr_factors:
        assert system._combine_decryption_factors(factors_collections) == 0
    else:
        assert system._combine_decryption_factors(factors_collections) == [
            reduce(lambda x, y: x * y, [elems[i][j] for i in range(nr_trustees)]) for j in range(nr_factors)
        ]

# Decryption-factors verification

__system__ciphers__secret__public = []

for (system, key) in (
    (RES11_SYSTEM, RES11_KEY), (_2048_SYSTEM, _2048_KEY), (_4096_SYSTEM, _4096_KEY)):
    group = system.group
    ciphers = [{'alpha': group.random_element(), 'beta': group.random_element()}
        for _ in range(random_integer(2, 12))]
    secret = mpz(key)
    public = group.generate(secret)

    __system__ciphers__secret__public.append((system, ciphers, secret, public))

@pytest.mark.parametrize('system, ciphers, secret, public',
    __system__ciphers__secret__public)
def test__computation_and_verification_of_decryption_factors(system, ciphers, secret, public):
    factors = system._compute_decryption_factors(secret, ciphers)
    assert system._verify_decryption_factors(public, ciphers, factors)

__failure_cases = []

for (system, key) in (
    (RES11_SYSTEM, RES11_KEY), (_2048_SYSTEM, _2048_KEY), (_4096_SYSTEM, _4096_KEY)):
    group = system.group
    ciphers = [{'alpha': group.random_element(), 'beta': group.random_element()}
        for _ in range(random_integer(2, 12))]
    secret = mpz(key)
    public = group.generate(secret)
    factors = system._compute_decryption_factors(secret, ciphers)

    # Corrupt ciphers
    corrupt_ciphers = ciphers[:]
    corrupt_alpha = corrupt_ciphers[0]['alpha'].clone()
    corrupt_alpha.reduce_value()
    corrupt_ciphers[0] = {'alpha': corrupt_alpha, 'beta': ciphers[0]['beta']}
    __failure_cases.append((system, public, corrupt_ciphers, factors))

    # Corrput lengths
    corrupt_ciphers = ciphers[:]
    del corrupt_ciphers[-1]
    __failure_cases.append((system, public, corrupt_ciphers, factors))

    # Corrupt secret
    corrupt_secret = secret + 1
    corrupt_factors = system._compute_decryption_factors(corrupt_secret, ciphers)
    __failure_cases.append((system, public, ciphers, corrupt_factors))

    # Corrupt public
    corrupt_public = public.clone()
    corrupt_public.reduce_value()
    __failure_cases.append((system, corrupt_public, ciphers, factors))

@pytest.mark.parametrize('system, public, ciphers, factors', __failure_cases)
def test__failure_at_verification_of_decryption_factors(system, public, ciphers, factors):
    assert not system._verify_decryption_factors(public, ciphers, factors)


# Trustees' factors validation

# __system__mixed_ballots__trustee_keypair = []
# for (system, ciphers, secret, public) in __system__ciphers__secret__public:
#     mixed_ballots = ciphers
#     trustee_keypair = system._set_keypair(secret, public)
#     __system__mixed_ballots__trustee_keypair.append((system, mixed_ballots, trustee_keypair))
#
# @pytest.mark.parametrize('system, mixed_ballots, trustee_keypair',
#     __system__mixed_ballots__trustee_keypair)
# def test_validate_trustee_factors(system, mixed_ballots, trustee_keypair):
#     trustee_factors = system.compute_trustee_factors(mixed_ballots, trustee_keypair)
#     assert system.validate_trustee_factors(mixed_ballots, trustee_factors)

__system__mixed_ballots__trustee_keypair__trustee_public = []
for (system, ciphers, secret, public) in __system__ciphers__secret__public:
    mixed_ballots = ciphers
    trustee_keypair = system._set_keypair(secret, public)
    trustee_public = public
    __system__mixed_ballots__trustee_keypair__trustee_public\
        .append((system, mixed_ballots, trustee_keypair, trustee_public))

@pytest.mark.parametrize('system, mixed_ballots, trustee_keypair, trustee_public',
    __system__mixed_ballots__trustee_keypair__trustee_public)
def test_validate_trustee_factors(system, mixed_ballots, trustee_keypair, trustee_public):
    trustee_factors = system.compute_trustee_factors(mixed_ballots, trustee_keypair)
    assert system.validate_trustee_factors(trustee_public, mixed_ballots, trustee_factors)

__failure_cases__ = []

for (system, key) in (
    (RES11_SYSTEM, RES11_KEY),
    (_2048_SYSTEM, _2048_KEY),
    (_4096_SYSTEM, _4096_KEY),
):
    group = system.group
    mixed_ballots = [{'alpha': group.random_element(), 'beta': group.random_element()}
        for _ in range(random_integer(2, 12))]
    trustee_private = mpz(key)
    trustee_public = group.generate(trustee_private)
    trustee_factors = system.compute_trustee_factors(mixed_ballots, {
        'private': trustee_private,
        'public': trustee_public
    })

    # Corrupt ballots
    corrupt_ballots = mixed_ballots[:]
    corrupt_alpha = corrupt_ballots[0]['alpha'].clone()
    corrupt_alpha.reduce_value()
    corrupt_ballots[0] = {'alpha': corrupt_alpha, 'beta': mixed_ballots[0]['beta']}
    __failure_cases__.append((system, trustee_public, corrupt_ballots, trustee_factors))

    # Corrput lengths
    corrupt_ballots = mixed_ballots[:]
    del corrupt_ballots[-1]
    __failure_cases__.append((system, trustee_public, corrupt_ballots, trustee_factors))

    # Wrong private key
    corrupt_private = trustee_private + 1
    corrupt_factors = system.compute_trustee_factors(mixed_ballots, {
        'private': corrupt_private,
        'public': trustee_public
    })
    __failure_cases__.append((system, trustee_public, mixed_ballots, corrupt_factors))

    # Corrupt public key
    corrupt_public = trustee_public.clone()
    corrupt_public.reduce_value()
    from crypto import ModPrimeElement
    __failure_cases__.append((system, corrupt_public, mixed_ballots, trustee_factors))

@pytest.mark.parametrize('system, trustee_public, mixed_ballots, trustee_factors', __failure_cases__)
def test__failure_at_validation_of_trustee_factors(system, trustee_public,
        mixed_ballots, trustee_factors):
    print(trustee_public)
    with pytest.raises(InvalidFactorsError):
        system.validate_trustee_factors(trustee_public, mixed_ballots, trustee_factors)


# Ballot decryption

__system__mixed_ballots__zeus_factors__trustees_factors__expecteds = []

for system in (
    RES11_SYSTEM,
    _2048_SYSTEM,
    _4096_SYSTEM,
):
    nr_ballots = 20
    nr_trustees = 4
    random_element = system.group.random_element

    # Mock zeus and trustees
    zeus_factors = [{'data': random_element().value, 'proof': {}} for _ in range(nr_ballots)]
    trustees_factors = [[{'data': random_element().value, 'proof': {}} for _ in range(nr_ballots)] for _ in range(nr_trustees)]

    # Combine componentwise to get decryption factors
    decryption_factors = []
    trustees_factors.append(zeus_factors)
    decryption_factors = system._combine_decryption_factors(trustees_factors)

    # Mock mixed ballots
    mixed_ballots = [{'alpha': random_element(), 'beta': random_element()} for _ in range(nr_ballots)]

    # Decrypt
    expecteds = [(decryptor.inverse * ballot['beta']).to_integer()
        for (ballot, decryptor) in zip(mixed_ballots, decryption_factors)]

    # Append parameters
    __system__mixed_ballots__zeus_factors__trustees_factors__expecteds\
        .append((system, mixed_ballots, zeus_factors, trustees_factors, expecteds))

@pytest.mark.parametrize('system, mixed_ballots, zeus_factors, trustees_factors, expecteds',
    __system__mixed_ballots__zeus_factors__trustees_factors__expecteds)
def test_decrypt_ballots(system, mixed_ballots, zeus_factors, trustees_factors, expecteds):
    assert True
