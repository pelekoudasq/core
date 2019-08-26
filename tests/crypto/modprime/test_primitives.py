import pytest

from gmpy2 import mpz, invert

from crypto.constants import (_2048_KEY, _2048_PUBLIC, _2048_DDH,
                              _4096_KEY, _4096_PUBLIC, _4096_DDH)
from crypto.modprime import ModPrimeElement

from tests.constants import _2048_SYSTEM, _4096_SYSTEM


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


_system = [_2048_SYSTEM, _4096_SYSTEM]

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
        239384877347538475938475384987497929929846663728917735493874593847593875,
        _2048_KEY,
        _2048_PUBLIC,
        True
    ),
    (
        _2048_SYSTEM,
        239384877347538475938475384987497929929846663728917735493874593847593875,
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
    'system, element, public_key, private_key', _system_element_key)
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
    'system, element, public_key, private_key', _system_element_key)
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
    'system, element, public_key, private_key', _system_element_key)
def test_encryption_with_randomness_and_proof(system, element, public_key, private_key):

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
    'system, element, public_key, private_key', _system_element_key)
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


# mod 11 setup

from tests.constants import RES11_SYSTEM

system = RES11_SYSTEM
group = system.group
modulus = group.modulus                    # p

__ciphertext__public__secret__decoded = []

for _ in range(10):

    beta = group.random_element()
    public = group.random_element()
    secret = group.random_exponent()

    ciphertext = {
        'alpha': group.random_element(),
        'beta': beta
    }

    encoded = (public ** secret).inverse * beta

    b = beta.value
    y = public.value
    x = secret

    if group.contains(encoded):
        # (y ^ x) ^ -1 * b - 1 (mod p)
        decoded = ((invert(y ** x, modulus) * b) % modulus - 1) % modulus
    else:
        # (-(y ^ x) ^ -1 * b (mod p)) - 1 (mod p)
        decoded = (-(invert(y ** x, modulus) * b) % modulus - 1) % modulus

    decoded = ModPrimeElement(decoded, modulus)

    __ciphertext__public__secret__decoded.append(
        (ciphertext, public, secret, decoded))


@pytest.mark.parametrize('ciphertext, public, secret, decoded',
    __ciphertext__public__secret__decoded)
def test_decryption_with_randomness(ciphertext, public, secret, decoded):
    assert decoded == \
        system._decrypt_with_randomness(ciphertext, public, secret)
