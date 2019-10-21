import pytest
from copy import deepcopy
from gmpy2 import mpz, powmod, invert

from zeus_core.crypto.modprime import ModPrimeElement
from zeus_core.crypto.exceptions import InvalidKeyError
from zeus_core.utils.random import random_integer

from tests.constants import (MESSAGE,
    RES11_SYSTEM, RES11_KEY, RES11_PUBLIC, RES11_DDH,
    _2048_SYSTEM, _2048_SECRET, _2048_PUBLIC, _2048_DDH,
    _4096_SYSTEM, _4096_SECRET, _4096_PUBLIC, _4096_DDH)


# Schnorr protocol

extras = [0, 7, 11, 666]

__system__proof__public__extras__verified = []

for (system, secret) in (
    (_2048_SYSTEM, _2048_SECRET),
    (_4096_SYSTEM, _4096_SECRET),
):
    secret = mpz(secret)
    public = system.group.generate(secret)

    # Valid case
    proof = system._schnorr_proof(secret, public, *extras)
    __system__proof__public__extras__verified.append(
        (system, proof, public, extras, True))

    # Corrupt logarithm
    corrupt_secret = secret + 1
    corrupt_proof = system._schnorr_proof(corrupt_secret, public, *extras)
    __system__proof__public__extras__verified.append(
        (system, corrupt_proof, public, extras, False))

    # Corrupt extras
    corrupt_extras = deepcopy(extras)
    corrupt_extras[0] += 1
    __system__proof__public__extras__verified.append(
        (system, proof, public, corrupt_extras, False))

    # Corrupt proof by tampering commitment
    corrupt_proof = deepcopy(proof)
    corrupt_proof['commitment'].reduce_value()
    __system__proof__public__extras__verified.append(
        (system, corrupt_proof, public, extras, False))

    # Corrupt proof by tampering challenge
    corrupt_proof = deepcopy(proof)
    corrupt_proof['challenge'] += 1
    __system__proof__public__extras__verified.append(
        (system, corrupt_proof, public, extras, False))

    # Corrupt proof by tampering response
    corrupt_proof = deepcopy(proof)
    corrupt_proof['response'] += 1
    __system__proof__public__extras__verified.append(
        (system, corrupt_proof, public, extras, False))

@pytest.mark.parametrize('system, proof, public, extras, verified',
    __system__proof__public__extras__verified)
def test_schnorr_protocol(system, proof, public, extras, verified):
    assert system._schnorr_verify(proof, public, *extras) is verified


# Chaum-Pedersen protocol

__system__ddh__z__result = []

for (system, DDH) in (
    (_2048_SYSTEM, _2048_DDH),
    (_4096_SYSTEM, _4096_DDH),
):
    modulus = system.group.modulus

    ddh = [ModPrimeElement(elem, modulus) for elem in DDH['ddh']]
    z = mpz(DDH['log'])
    __system__ddh__z__result.append((system, ddh, z, True))

    # Invalidate tuple by corrupting first member
    corrupt = ddh[0].clone()
    corrupt.reduce_value()
    corrupt_ddh = [corrupt, ddh[1], ddh[2]]
    __system__ddh__z__result.append((system, corrupt_ddh, z, False))

    # Invalidate tuple by corrupting second member
    corrupt = ddh[1].clone()
    corrupt.reduce_value()
    corrupt_ddh = [ddh[0], corrupt, ddh[2]]
    __system__ddh__z__result.append((system, corrupt_ddh, z, False))

    # Invalidate tuple by corrupting third member
    corrupt = ddh[2].clone()
    corrupt.reduce_value()
    corrupt_ddh = [ddh[0], ddh[1], corrupt]
    __system__ddh__z__result.append((system, corrupt_ddh, z, False))

    # Corrupt logarithm
    __system__ddh__z__result.append((system, ddh, z - 1, False))

@pytest.mark.parametrize('system, ddh, z, result', __system__ddh__z__result)
def test_chaum_pedersen_protocol(system, ddh, z, result):
    proof = system._chaum_pedersen_proof(ddh, z)
    valid = system._chaum_pedersen_verify(ddh, proof)

    assert valid is result


# Key generation

def test_keygen_with_InvalidKeyError():
    with pytest.raises(InvalidKeyError):
        _2048_SYSTEM.keygen(_2048_SYSTEM.group.order)

@pytest.mark.parametrize('system', [_2048_SYSTEM, _4096_SYSTEM,])
def test_keygen_with_random_private(system):
    keypair = system.keygen()
    _, public_key = system.extract_keypair(keypair)
    public_key, proof = system._extract_public_key(public_key)

    assert system._schnorr_verify(proof, public_key)


__system__secret__public = [
    (_2048_SYSTEM, _2048_SECRET, _2048_PUBLIC),
    (_4096_SYSTEM, _4096_SECRET, _4096_PUBLIC),
]

@pytest.mark.parametrize('system, secret, public', __system__secret__public)
def test_keygen_with_non_random_private(system, secret, public):
    keypair = system.keygen(secret)
    _, public_key = system.extract_keypair(keypair)
    public_key, proof = system._extract_public_key(public_key)

    valid = system._schnorr_verify(proof, public_key)
    assert secret == keypair['private'] and public_key.value == public and valid


# Key validation

__system__public_key__result = []

for system in (
    _2048_SYSTEM,
    _4096_SYSTEM
):
    public_key = system.keygen()['public']
    __system__public_key__result.append((system, public_key, True))

    # Corrupt key value
    corrupt_value = public_key['value'].clone()
    corrupt_value.reduce_value()
    corrupt_public_key = {'value': corrupt_value, 'proof': public_key['proof']}
    __system__public_key__result.append((system, corrupt_public_key, False))

    # Corrupt key proof
    corrupt_proof = deepcopy(public_key['proof'])
    corrupt_proof['challenge'] += 100
    corrupt_public_key = {'value': public_key['value'], 'proof': corrupt_proof}
    __system__public_key__result.append((system, corrupt_public_key, False))

@pytest.mark.parametrize('system, public_key, result', __system__public_key__result)
def test_validate_public_key(system, public_key, result):
    assert system.validate_public_key(public_key) is result


# Digital Signature Algorithm

exponent = 919228301823987238476870928301982103978254287481928123817398172931839120

__system__exponent__signature__public_key__verified = []

for (system, private_key) in (
    (_2048_SYSTEM, _2048_SECRET),
    (_4096_SYSTEM, _4096_SECRET),
):
    keypair = system.keygen(mpz(private_key))
    private_key, public_key = system.extract_keypair(keypair)
    public_key = system.get_key_value(public_key)

    exponent = mpz(exponent)

    # Valid case
    signature = system._dsa_signature(exponent, private_key)
    __system__exponent__signature__public_key__verified.append(
        (system, exponent, signature, public_key, True))

    # Invalid identity (Authentication check)
    wrong_secret = private_key + 1
    signature = system._dsa_signature(exponent, wrong_secret)
    __system__exponent__signature__public_key__verified.append(
        (system, exponent, signature, public_key, False))

    # Tampered message (Integrity check)
    signature = system._dsa_signature(exponent, private_key)
    __system__exponent__signature__public_key__verified.append(
        (system, exponent + 1, signature, public_key, False))

    # Invalid commitments
    signature = system._dsa_signature(exponent, private_key)
    signature['commitments']['c_1'] = system.group.order
    __system__exponent__signature__public_key__verified.append(
        (system, exponent, signature, public_key, False))

@pytest.mark.parametrize('system, exponent, signature, public_key, verified',
    __system__exponent__signature__public_key__verified)
def test_text_message_signature(system, exponent, signature, public_key, verified):
    assert system._dsa_verify(exponent, signature, public_key) is verified


# Text-message signatures

__system__signed_message__public_key__verified = []

for (system, private_key) in (
    (_2048_SYSTEM, _2048_SECRET),
    (_4096_SYSTEM, _4096_SECRET),
):
    keypair = system.keygen(mpz(private_key))

    # Valid case
    private_key, public_key = system.extract_keypair(keypair)
    message = MESSAGE
    signed_message = system.sign_text_message(message, private_key)
    __system__signed_message__public_key__verified.append(
        (system, signed_message, public_key, True))

    # Invalid identity (Authentication check)
    wrong_secret = private_key + 1
    signed_message = system.sign_text_message(message, wrong_secret)
    __system__signed_message__public_key__verified.append(
        (system, signed_message, public_key, False))

    # Tampered message (Integrity check)
    signed_message = system.sign_text_message(message, private_key)
    signed_message['message'] += '__corrupt_part'
    __system__signed_message__public_key__verified.append(
        (system, signed_message, public_key, False))

@pytest.mark.parametrize('system, signed_message, public_key, verified',
    __system__signed_message__public_key__verified)
def test_text_message_signature(system, signed_message, public_key, verified):
    assert system.verify_text_signature(signed_message, public_key) is verified


# El-Gamal encryption

__element = 792387492873492873492879428794827973465837687123194802943820394774576454

__system__element__private_key__public_key = []

for (system, private_key) in (
    (_2048_SYSTEM, _2048_SECRET),
    (_4096_SYSTEM, _4096_SECRET),
):
    element = ModPrimeElement(mpz(__element), system.group.modulus)
    keypair = system.keygen(private_key)
    private_key, public_key = system.extract_keypair(keypair)
    public_key = system.get_key_value(public_key)

    __system__element__private_key__public_key.append(
        (system, element, private_key, public_key))

@pytest.mark.parametrize('system, element, private_key, public_key',
    __system__element__private_key__public_key)
def test_encryption(system, element, private_key, public_key):
    ciphertext = system.encrypt(element, public_key)
    original = system._decrypt(ciphertext, private_key)

    assert element == original

@pytest.mark.parametrize('system, element, private_key, public_key',
    __system__element__private_key__public_key)
def test_encryption_with_secret_and_proof(system, element, private_key, public_key):
    ciphertext, randomness = system.encrypt(element, public_key, get_secret=True)
    proof = system.prove_encryption(ciphertext, randomness)
    ciphertext_proof = system.set_ciphertext_proof(ciphertext, proof)
    verified = system.verify_encryption(ciphertext_proof)

    assert verified

__system__ciphertext_proof__verified = []
__system__ciphertext__decryptor__element = []

for (system, element, private_key, public_key) in __system__element__private_key__public_key:
    print(type(element))
    print(type(public_key))
    ciphertext, randomness = system.encrypt(element, public_key, get_secret=True)
    proof = system.prove_encryption(ciphertext, randomness)
    ciphertext_proof = system.set_ciphertext_proof(ciphertext, proof)

    # Encryption proof

    # Valid case
    __system__ciphertext_proof__verified.append(
        (system, ciphertext_proof, True))

    # Corrupt ciphertext by tampering devryptor
    ciphertext, proof = system.extract_ciphertext_proof(ciphertext_proof)
    corrupt_ciphertext = deepcopy(ciphertext)
    corrupt_ciphertext['alpha'].reduce_value()
    corrupt_ciphertext_proof = system.set_ciphertext_proof(corrupt_ciphertext, proof)
    __system__ciphertext_proof__verified.append(
        (system, corrupt_ciphertext_proof, False))

    # Corrupt ciphertext by tampering beta
    ciphertext, proof = system.extract_ciphertext_proof(ciphertext_proof)
    corrupt_ciphertext = deepcopy(ciphertext)
    corrupt_ciphertext['beta'].reduce_value()
    corrupt_ciphertext_proof = system.set_ciphertext_proof(corrupt_ciphertext, proof)
    __system__ciphertext_proof__verified.append(
        (system, corrupt_ciphertext_proof, False))

    # Corrupt proof by tampering commitment
    ciphertext, proof = system.extract_ciphertext_proof(ciphertext_proof)
    corrupt_proof = deepcopy(proof)
    corrupt_proof['commitment'].reduce_value()
    corrupt_ciphertext_proof = system.set_ciphertext_proof(ciphertext, corrupt_proof)
    __system__ciphertext_proof__verified.append(
        (system, corrupt_ciphertext_proof, False))

    # Corrupt proof by tampering challenge
    ciphertext, proof = system.extract_ciphertext_proof(ciphertext_proof)
    corrupt_proof = deepcopy(proof)
    corrupt_proof['challenge'] += 1
    corrupt_ciphertext_proof = system.set_ciphertext_proof(ciphertext, corrupt_proof)
    __system__ciphertext_proof__verified.append(
        (system, corrupt_ciphertext_proof, False))

    # Corrupt proof by tampering response
    ciphertext, proof = system.extract_ciphertext_proof(ciphertext_proof)
    corrupt_proof = deepcopy(proof)
    corrupt_proof['response'] += 1
    corrupt_ciphertext_proof = system.set_ciphertext_proof(ciphertext, corrupt_proof)
    __system__ciphertext_proof__verified.append(
        (system, corrupt_ciphertext_proof, False))

    # Decryption

    alpha, _ = system.extract_ciphertext(ciphertext)
    decryptor = alpha ** private_key
    __system__ciphertext__decryptor__element.append(
        (system, ciphertext, decryptor, element))

@pytest.mark.parametrize('system, ciphertext_proof, verified',
    __system__ciphertext_proof__verified)
def testverify_encryption(system, ciphertext_proof, verified):
    assert system.verify_encryption(ciphertext_proof) is verified

@pytest.mark.parametrize('system, ciphertext, decryptor, element',
    __system__ciphertext__decryptor__element)
def test_decrypt_with_decryptor(system, ciphertext, decryptor, element):
    assert system._decrypt_with_decryptor(ciphertext, decryptor) == element


__system__ciphertext__public__secret__decoded = []

for system in (
    RES11_SYSTEM,
    _2048_SYSTEM,
    _4096_SYSTEM
):
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

        # if group.contains(encoded):
        if group.order > encoded.value:
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
        system.decrypt_with_randomness(ciphertext, public, secret)


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

    final = system.encrypt(element, public_key, randomness=sum(randoms))

    __ciphertext = system.encrypt(element, public_key, randomness=randoms[0])
    for random in randoms[1:]:
        __ciphertext = system._reencrypt(__ciphertext, public_key, randomness=random)

    assert __ciphertext == final
