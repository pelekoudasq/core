import pytest
from copy import deepcopy
from gmpy2 import mpz, powmod, invert

from crypto.modprime import ModPrimeElement
from utils.random import random_integer

from tests.constants import (MESSAGE, RES11_SYSTEM, RES11_KEY, RES11_PUBLIC,
    _2048_SYSTEM, _2048_KEY, _2048_PUBLIC, _2048_DDH,
    _4096_SYSTEM, _4096_KEY, _4096_PUBLIC, _4096_DDH)


# Key generation and validation

__system__secret__public = [
    (RES11_SYSTEM, RES11_KEY, RES11_PUBLIC),
    (_2048_SYSTEM, _2048_KEY, _2048_PUBLIC),
    (_4096_SYSTEM, _4096_KEY, _4096_PUBLIC)
]

@pytest.mark.parametrize('system, secret, public', __system__secret__public)
def test_keygen_with_non_random_private(system, secret, public):
    keypair = system.keygen(private_key=secret)
    public_key = keypair['public']
    proof = public_key['proof']
    public_key = public_key['value']

    valid = system._schnorr_verify(proof, public_key)

    assert secret == keypair['private'] and public_key.value == public and valid


__system = [RES11_SYSTEM, _2048_SYSTEM, _4096_SYSTEM]

@pytest.mark.parametrize('system', __system)
def test_keygen_with_random_private(system):
    keypair = system.keygen()
    public_key = keypair['public']
    proof = public_key['proof']
    public_key = public_key['value']

    assert system._schnorr_verify(proof, public_key)


__system__public_key__result = []

for system in (RES11_SYSTEM, _2048_SYSTEM, _4096_SYSTEM):
    public_key = system.keygen()['public']
    __system__public_key__result.append((system, public_key, True))

    # Corrupt key
    corrupt_value = public_key['value'].clone()
    corrupt_value.reduce_value()
    corrupt_public_key = {'value': corrupt_value, 'proof': public_key['proof']}
    __system__public_key__result.append((system, corrupt_public_key, False))

    # Corrupt proof
    corrupt_proof = deepcopy(public_key['proof'])
    corrupt_proof['challenge'] += 100
    corrupt_public_key = {'value': public_key['value'], 'proof': corrupt_proof}
    __system__public_key__result.append((system, corrupt_public_key, False))

@pytest.mark.parametrize('system, public_key, result', __system__public_key__result)
def test_validate_public_key(system, public_key, result):
    assert system.validate_public_key(public_key) is result


# Digital signatures

__system__exponent__keys__result = [
    (
        _2048_SYSTEM,
        239384877347538475938475384987497929929846663728917735493874593847593875,
        _2048_KEY,
        _2048_PUBLIC,
        True
    ),
    (
        _2048_SYSTEM,
        239384877347538475938475384987497929929846663728917735493874593847593875,
        _2048_KEY - 1,                                       # Wrong private key
        _2048_PUBLIC,
        False
    ),
    (
        _4096_SYSTEM,
        919228301823987238476870928301982103978254287481928123817398172931839120,
        _4096_KEY,
        _4096_PUBLIC,
        True
    ),
    (
        _4096_SYSTEM,
        919228301823987238476870928301982103978254287481928123817398172931839120,
        _4096_KEY - 1,                                       # Wrong private key
        _4096_PUBLIC,
        False
    ),
]

@pytest.mark.parametrize('system, exponent, private_key, public_key, result',
    __system__exponent__keys__result)
def test_dsa_signature(system, exponent, private_key, public_key, result):

    private_key = mpz(private_key)
    public_key = ModPrimeElement(value=public_key, modulus=system.group.modulus)

    signature = system._dsa_signature(exponent, private_key)
    verified = system._dsa_verify(exponent, signature, public_key)

    assert verified is result


_system_message_key__bool = [
    (
        _2048_SYSTEM,
        MESSAGE,
        _2048_KEY,
        _2048_PUBLIC,
        True
    ),
    (
        _2048_SYSTEM,
        MESSAGE,
        _2048_KEY - 1,                                       # Wrong private key
        _2048_PUBLIC,
        False
    ),
    (
        _4096_SYSTEM,
        MESSAGE,
        _4096_KEY,
        _4096_PUBLIC,
        True
    ),
    (
        _4096_SYSTEM,
        MESSAGE,
        _4096_KEY - 1,                                       # Wrong private key
        _4096_PUBLIC,
        False
    ),
]

@pytest.mark.parametrize(
    'system, message, private_key, public_key, _bool', _system_message_key__bool)
def test_text_message_signature(system, message, private_key, public_key, _bool):

    private_key = mpz(private_key)
    public_key = {
        'value': ModPrimeElement(value=public_key, modulus=system.group.modulus),
        'proof': {
            'whatever': '... attached proof plays no role here...'
            # ...
        }
    }

    signed_message = system.sign_text_message(message, private_key)
    verified = system.verify_text_signature(signed_message, public_key)

    assert verified is _bool


# Schnorr protocol

__system__secret__public__extras__result = [
    (
        _2048_SYSTEM,
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
    (
        _2048_SYSTEM,
        12345,                                                 # Wrong logarithm
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        False
    ),
    (
        _2048_SYSTEM,
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [1, 7, 11, 666],                                       # Wrong extras
        False
    ),
    (
        _4096_SYSTEM,
        _4096_KEY,
        _4096_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
    (
        _4096_SYSTEM,
        12345,                                                 # Wrong logarithm
        _4096_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        False
    ),
    (
        _4096_SYSTEM,
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [1, 7, 11, 666],                                       # Wrong extras
        False
    ),
]

@pytest.mark.parametrize('system, secret, public, extras_1, extras_2, result',
    __system__secret__public__extras__result)
def test_schnorr_protocol(system, secret, public, extras_1, extras_2, result):

    secret = mpz(secret)
    public = ModPrimeElement(public, system.group.modulus)

    proof = system._schnorr_proof(secret, public, *extras_1)
    valid = system._schnorr_verify(proof, public, *extras_2)

    assert valid is result


# Chaum-Pedersen protocol

__system__ddh__z__result = [
    (
        _2048_SYSTEM,
        _2048_DDH['ddh'],
        _2048_DDH['log'],
        True
    ),
    (
        _2048_SYSTEM,
        _4096_DDH['ddh'],
        _2048_DDH['log'],
        False                                                  # Wrong logarithm
    ),
    (
        _4096_SYSTEM,
        _4096_DDH['ddh'],
        _4096_DDH['log'],
        True
    ),
    (
        _4096_SYSTEM,
        _2048_DDH['ddh'],
        _4096_DDH['log'],
        False                                                  # Wrong logarithm
    ),
]

@pytest.mark.parametrize('system, ddh, z, result', __system__ddh__z__result)
def test_chaum_pedersen_protocol(system, ddh, z, result):

    ddh = [ModPrimeElement(_, system.group.modulus) for _ in ddh]

    proof = system._chaum_pedersen_proof(ddh, z)
    valid = system._chaum_pedersen_verify(ddh, proof)

    assert valid is result


# El-Gamal encryption

__system__element__keys = [
    (
        _2048_SYSTEM,
        792387492873492873492879428794827973465837687123194802943820394774576454,
        _2048_PUBLIC,
        _2048_KEY
    ),
    (
        _4096_SYSTEM,
        792387492873492873492879428794827973465837687123194802943820394774576454,
        _4096_PUBLIC,
        _4096_KEY
    )
]

@pytest.mark.parametrize('system, element, public_key, private_key',
    __system__element__keys)
def test_encryption(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)
    private_key = mpz(private_key)

    # Ecnryption/Decryption
    ciphertext = system._encrypt(element, public_key)
    original = system._decrypt(ciphertext, private_key)

    assert element == original


@pytest.mark.parametrize(
    'system, element, public_key, private_key', __system__element__keys)
def test_valid_encryption_proof(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)

    # Ecnryption/Proof validation
    randomness = system.group.random_exponent()
    ciphertext = system._encrypt(element, public_key, randomness)
    proof = system._prove_encryption(ciphertext, randomness)
    ciphertext_proof = system._set_ciphertext_proof(ciphertext, proof)
    verified = system._verify_encryption(ciphertext_proof)

    assert verified

@pytest.mark.parametrize(
    'system, element, public_key, private_key', __system__element__keys)
def test_invalid_encryption_proof(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)

    # Ecnryption/Proof validation

    randomness = system.group.random_exponent()
    ciphertext = system._encrypt(element, public_key, randomness)

    # Corrupt ciphertext by tampering alpha
    alpha, beta = system._extract_ciphertext(ciphertext)
    alpha = ModPrimeElement(alpha.value + 1, system.group.modulus)
    corrupted_ciphertext = system._set_ciphertext(alpha, beta)

    proof = system._prove_encryption(ciphertext, randomness)
    ciphertext_proof = system._set_ciphertext_proof(corrupted_ciphertext, proof)
    verified = system._verify_encryption(ciphertext_proof)

    assert not verified

@pytest.mark.parametrize(
    'system, element, public_key, private_key', __system__element__keys)
def test_encryption_with_secret_and_proof(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)

    # Encryption/Proof validation
    ciphertext, randomness = system._encrypt(element, public_key, get_secret=True)
    proof = system._prove_encryption(ciphertext, randomness)
    ciphertext_proof = system._set_ciphertext_proof(ciphertext, proof)
    verified = system._verify_encryption(ciphertext_proof)

    assert verified

@pytest.mark.parametrize(
    'system, element, public_key, private_key', __system__element__keys)
def test_decryption_with_decryptor(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)
    private_key = mpz(private_key)

    # Ecnryption
    ciphertext = system._encrypt(element, public_key)

    # ~ Decrypt with decryptor alpha ^ x (specializes to
    # ~ standard ElGamal decryption for testing purposes)
    alpha, _ = system._extract_ciphertext(ciphertext)
    decryptor = alpha ** private_key
    decrypted = system._decrypt_with_decryptor(ciphertext, decryptor)

    assert element == decrypted


__system__ciphertext__public__secret__decoded = []

for system in (RES11_SYSTEM, _2048_SYSTEM, _4096_SYSTEM):
    group = system.group
    modulus = group.modulus

    for _ in range(10):

        beta = group.random_element()
        public = group.random_element()
        secret = group.random_exponent()

        ciphertext = {'alpha': group.random_element(), 'beta': beta}

        encoded = (public ** secret).inverse * beta

        b = beta.value
        y = public.value
        x = secret

        if group.contains(encoded):
            # (y ^ x) ^ -1 * b - 1 (mod p)
            decoded = ((invert(powmod(y, x, modulus), modulus) * b) % modulus - 1) % modulus
        else:
            # (-(y ^ x) ^ -1 * b (mod p)) - 1 (mod p)
            decoded = (-(invert(powmod(y, x, modulus), modulus) * b) % modulus - 1) % modulus

        decoded = ModPrimeElement(decoded, modulus)

        __system__ciphertext__public__secret__decoded.append(
            (system, ciphertext, public, secret, decoded))


@pytest.mark.parametrize('system, ciphertext, public, secret, decoded',
    __system__ciphertext__public__secret__decoded)
def test_decryption_with_randomness(system, ciphertext, public, secret, decoded):
    assert decoded == \
        system._decrypt_with_randomness(ciphertext, public, secret)


# Re-encryption

__system__element__public_key__randoms = []

for system in (RES11_SYSTEM, _2048_SYSTEM, _4096_SYSTEM):
    group = system.group

    element = group.random_element()
    public_key = group.random_element()
    randoms = [group.random_exponent() for _ in range(random_integer(1, 12))]

    __system__element__public_key__randoms.append(
        (system, element, public_key, randoms))

@pytest.mark.parametrize('system, element, public_key, randoms',
    __system__element__public_key__randoms)
def test__reencrypt(system, element, public_key, randoms):

    final = system._encrypt(element, public_key, randomness=sum(randoms))

    __ciphertext = system._encrypt(element, public_key, randomness=randoms[0])
    for random in randoms[1:]:
        __ciphertext = system._reencrypt(__ciphertext, public_key, randomness=random)

    assert __ciphertext == final
