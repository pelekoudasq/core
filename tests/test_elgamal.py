import pytest

from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC, _2048_DDH,
                              _4096_PRIME, _4096_ELEMENT, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC, _4096_DDH)
from crypto.exceptions import WrongCryptoError, WeakCryptoError
from crypto.modprime import ModPrimeCrypto

_2048_SYSTEM = ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT)
_4096_SYSTEM = ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT)



_cls_config_order_generator = [
    (
        ModPrimeCrypto,
        {
            'modulus': _2048_PRIME,
            'element': _2048_ELEMENT,
            'root_order': 2
        },
        _2048_ORDER,
        _2048_GENERATOR
    ),
    (
        ModPrimeCrypto,
        {
            'modulus': _4096_PRIME,
            'element': _4096_ELEMENT,
            'root_order': 2
        },
        _4096_ORDER,
        _4096_GENERATOR
    )
]

@pytest.mark.parametrize(
    'cls, config, order, generator', _cls_config_order_generator)
def test_generate_system(cls, config, order, generator):

    system = cls.generate_system(config)

    assert system == {
        'modulus': config['modulus'],
        'order': order,
        'generator': generator
    }



_cls_system__bool = [
    (
        ModPrimeCrypto,
        {
            'modulus': _2048_PRIME,
            'order': _2048_ORDER,
            'generator': _2048_GENERATOR
        },
        True
    ),
    (
        ModPrimeCrypto,
        {
            'modulus': _4096_PRIME,
            'order': _4096_ORDER,
            'generator': _4096_GENERATOR
        },
        True
    ),
]

@pytest.mark.parametrize('cls, system, _bool', _cls_system__bool)
def test_validate_system(cls, system, _bool):

    validated = cls.validate_system(system)
    assert validated is _bool



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

    proof = system.schnorr_proof(secret, public, *extras_1)
    valid = system.schnorr_verify(proof, public, *extras_2)

    assert valid is _bool



_system_ddh_z__bool = [
    (
        _2048_SYSTEM, _2048_DDH['ddh'], _2048_DDH['log'], True
    ),
    (
        _4096_SYSTEM, _4096_DDH['ddh'], _4096_DDH['log'], True
    )
]

@pytest.mark.parametrize('system, ddh, z, _bool', _system_ddh_z__bool)
def test_chaum_pedersen_protocol(system, ddh, z, _bool):

    proof = system.chaum_pedersen_proof(ddh, z)
    valid = system.chaum_pedersen_verify(ddh, proof)

    assert valid is _bool



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

    private_key, public_key, proof = system.keygen(private_key=secret, schnorr=True)
    valid = system.schnorr_verify(proof, public_key)

    assert private_key == secret and public_key == public and valid



_system = [
    _2048_SYSTEM,
    _4096_SYSTEM
]

@pytest.mark.parametrize('system', _system)
def test_random_keygen(system):

    public_key, proof = system.keygen(schnorr=True)[1:]
    valid = system.schnorr_verify(proof, public_key)

    assert valid



_system_element_key = [
    (
        _2048_SYSTEM, 4458795847948730958739, _2048_KEY, _2048_PUBLIC
    ),
    (
        _4096_SYSTEM, 3737843847948750232978, _4096_KEY, _4096_PUBLIC
    ),
]

@pytest.mark.parametrize(
    'system, element, private_key, public_key', _system_element_key)
def test_element_signature(system, element, private_key, public_key):

    signature = system.sign_element(element, private_key)
    verified = system.verify_element_signature(signature, public_key)

    assert verified



_system_element_key = [
    (
        _2048_SYSTEM, 'kjkdfgkjdhfkgjhdkfjd', _2048_KEY, _2048_PUBLIC
    ),
    (
        _4096_SYSTEM, 'kdjfghkhelshfijaoiuv', _4096_KEY, _4096_PUBLIC
    ),
]

@pytest.mark.parametrize(
    'system, message, private_key, public_key', _system_element_key)
def test_text_message_signature(system, message, private_key, public_key):

    signed_message = system.sign_text_message(message, private_key)
    verified = system.verify_text_signature(signed_message, public_key)

    assert verified
