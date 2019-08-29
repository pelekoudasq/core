import pytest

from gmpy2 import mpz

from tests.constants import (RES11_SYSTEM, _2048_SYSTEM, _2048_KEY,
    _4096_SYSTEM, _4096_KEY)
from utils import random_integer


# Decryption-factors verification

__system__ciphers__secret__public = []

for (system, key) in (
    (RES11_SYSTEM, 7), (_2048_SYSTEM, _2048_KEY), (_4096_SYSTEM, _4096_KEY)):
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
    (RES11_SYSTEM, 7), (_2048_SYSTEM, _2048_KEY), (_4096_SYSTEM, _4096_KEY)):
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
