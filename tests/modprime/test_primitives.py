import pytest

from gmpy2 import mpz

from crypto.constants import (_2048_PRIME, _2048_PRIMITIVE, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC, _2048_DDH,
                              _4096_PRIME, _4096_PRIMITIVE, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC, _4096_DDH)
from crypto.exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto

_2048_SYSTEM = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(modulus=_4096_PRIME, primitive=_4096_PRIMITIVE)


# Underlying algebra

_original_inverse_modulus = [
    (1, 1, 2),
    (1, 1, 3), (2, 2, 3),
    (1, 1, 4), (3, 3, 4),
    (1, 1, 5), (2, 3, 5), (3, 2, 5), (4, 4, 5),
    (1, 1, 6), (5, 5, 6),
    (1, 1, 7), (2, 4, 7), (3, 5, 7), (4, 2, 7), (5, 3, 7), (6, 6, 7)
]

@pytest.mark.parametrize('original, inverse, modulus', _original_inverse_modulus)
def test_modular_inversion(original, inverse, modulus):

    original = ModPrimeElement(mpz(original), mpz(modulus))
    assert original.inverse.value == inverse

_AlgebraError_modulus_rootorder = [
    (0, 0),
    (1, 0), (1, 1),
    (2, 0), (2, 1), (2, 2),
    (3, 0), (3, 3),
    (4, 0), (4, 1), (4, 2), (4, 3), (4, 4),
    (5, 0), (5, 3), (5, 5),
    (7, 0), (7, 4), (7, 5), (7, 7),
    (11, 0), (11, 3), (11, 4), (11, 6), (11, 7), (11, 8), (11, 9), (11, 11)
]

@pytest.mark.parametrize('modulus, root_order', _AlgebraError_modulus_rootorder)
def test_AlgebraError_in_ModPrimeSubgroup_Construction(modulus, root_order):
    with pytest.raises(AlgebraError):
        ModPrimeSubgroup(modulus, root_order)


_modulus_rootorder_order = [
    (3, 1, 2), (3, 2, 1),
    (5, 1, 4), (5, 2, 2), (5, 4, 1),
    (7, 1, 6), (7, 2, 3), (7, 3, 2), (7, 6, 1),
    (11, 1, 10), (11, 2, 5), (11, 5, 2), (11, 10, 1),

    (_2048_PRIME, 2, _2048_ORDER), (_2048_PRIME, _2048_ORDER, 2),
    (_4096_PRIME, 2, _4096_ORDER), (_4096_PRIME, _4096_ORDER, 2),
]

@pytest.mark.parametrize('modulus, root_order, order', _modulus_rootorder_order)
def test_ModPrimeSubgroup_Construction(modulus, root_order, order):
    group = ModPrimeSubgroup(modulus, root_order)

    assert (group.modulus, group.order) == (modulus, order)


# Key generation and validation

_system_secret_public = [
    (
        _2048_SYSTEM, _2048_KEY, _2048_PUBLIC
    ),
    (
        _4096_SYSTEM, _4096_KEY, _4096_PUBLIC
    )
]

@pytest.mark.parametrize('system, secret, public', _system_secret_public)
def test_non_random_keygen(system, secret, public):

    key = system.keygen(private_key=secret)
    public_key = key['public']
    proof = public_key['proof']
    public_key = public_key['value']

    valid = system._schnorr_verify(proof, public_key)

    assert secret == key['private'] and public_key.value == public and valid

_system = [
    _2048_SYSTEM,
    _4096_SYSTEM
]

@pytest.mark.parametrize('system', _system)
def test_random_keygen(system):

    key = system.keygen()
    public_key = key['public']
    proof = public_key['proof']
    public_key = public_key['value']

    valid = system._schnorr_verify(proof, public_key)

    assert valid

@pytest.mark.parametrize('system', _system)
def test_validate_public_key(system):

    key = system.keygen()
    public_key = key['public']
    valid = system.validate_public_key(public_key)


# Digital signatures

_system_exponent_key__bool = [
    (
        _2048_SYSTEM,
        239384877347538475938475384987497493874593847593875,
        _2048_KEY,
        _2048_PUBLIC,
        True
    ),
    (
        _2048_SYSTEM,
        239384877347538475938475384987497493874593847593875,
        _2048_KEY - 1,
        _2048_PUBLIC,
        False                                                # Wrong private key
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
        _4096_KEY - 1,
        _4096_PUBLIC,
        False                                                # Wrong private key
    ),
]

@pytest.mark.parametrize(
    'system, exponent, private_key, public_key, _bool', _system_exponent_key__bool)
def test_dsa_signature(system, exponent, private_key, public_key, _bool):

    private_key = mpz(private_key)
    public_key = ModPrimeElement(value=public_key, modulus=system.group.modulus)

    signature = system._dsa_signature(exponent, private_key)
    verified = system._dsa_verify(exponent, signature, public_key)

    assert verified is _bool


_system_message_key__bool = [
    (
        _2048_SYSTEM,
        'kjkdfgkjdhfkgjhdkfjd',
        _2048_KEY,
        _2048_PUBLIC,
        True
    ),
    (
        _2048_SYSTEM,
        'kjkdfgkjdhfkgjhdkfjd',
        _2048_KEY - 1,
        _2048_PUBLIC,
        False                                                # Wrong private key
    ),
    (
        _4096_SYSTEM,
        'kdjfghkhelshfijaoiuv',
        _4096_KEY,
        _4096_PUBLIC,
        True
    ),
    (
        _4096_SYSTEM,
        'kdjfghkhelshfijaoiuv',
        _4096_KEY - 1,
        _4096_PUBLIC,
        False                                                # Wrong private key
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

_system_secret_public_extras__bool = [
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
        [1, 7, 11, 666],                                          # Wrong extras
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
        [1, 7, 11, 666],                                          # Wrong extras
        False
    ),
]

@pytest.mark.parametrize(
    'system, secret, public, extras_1, extras_2, _bool',
    _system_secret_public_extras__bool)
def test_schnorr_protocol(system, secret, public, extras_1, extras_2, _bool):

    secret = mpz(secret)
    public = ModPrimeElement(public, system.group.modulus)

    proof = system._schnorr_proof(secret, public, *extras_1)
    valid = system._schnorr_verify(proof, public, *extras_2)

    assert valid is _bool


# Chaum-Pedersen protocol

_system_ddh_z__bool = [
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

@pytest.mark.parametrize('system, ddh, z, _bool', _system_ddh_z__bool)
def test_chaum_pedersen_protocol(system, ddh, z, _bool):

    ddh = [ModPrimeElement(_, system.group.modulus) for _ in ddh]

    proof = system._chaum_pedersen_proof(ddh, z)
    valid = system._chaum_pedersen_verify(ddh, proof)

    assert valid is _bool


# El-Gamal encryption

_system_element_key = [
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

@pytest.mark.parametrize(
    'system, element, public_key, private_key', _system_element_key)
def test_encryption_decryption(system, element, public_key, private_key):

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
    'system, element, public_key, private_key', _system_element_key)
def test_encryption_proof(system, element, public_key, private_key):

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
    'system, element, public_key, private_key', _system_element_key)
def test_encryption_with_randomness_and_proof(system, element, public_key, private_key):

    __p = system.group.modulus

    # Type conversions
    element = ModPrimeElement(element, __p)
    public_key = ModPrimeElement(public_key, __p)

    # Encryption/Proof validation
    ciphertext, randomness = system._encrypt_with_randomness(element, public_key)
    proof = system._prove_encryption(ciphertext, randomness)
    ciphertext_proof = system._set_ciphertext_proof(ciphertext, proof)
    verified = system._verify_encryption(ciphertext_proof)

    assert verified