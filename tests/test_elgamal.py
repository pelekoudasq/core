import pytest

from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC,
                              _4096_PRIME, _4096_ELEMENT, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC)
from crypto.exceptions import WrongCryptoError, WeakCryptoError
from crypto.modprime import ModPrimeCrypto

_configs_and_params = [
    (
        _2048_PRIME,
        2,
        _2048_ELEMENT,
        _2048_ORDER,
        _2048_GENERATOR
    ),
    (
        _4096_PRIME,
        2,
        _4096_ELEMENT,
        _4096_ORDER,
        _4096_GENERATOR
    )
]

@pytest.mark.parametrize('modulus, root_order, element, order, generator', _configs_and_params)
def test_generate_system(modulus, root_order, element, order, generator):

    system = ModPrimeCrypto.generate_system(modulus, element, root_order)

    assert system == {
        'modulus': modulus,
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

    assert cls.validate_system(system) is _bool


_system_secret_public_extras__bool = [
    (
        ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT),
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
    (
        ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT),
        12345,                                                 # Wrong logarithm
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        False
    ),
    (
        ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT),
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [1, 7, 11, 666],                                          # Wrong extras
        False
    ),
    (
        ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT),
        _4096_KEY,
        _4096_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
    (
        ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT),
        12345,                                                 # Wrong logarithm
        _4096_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        False
    ),
    (
        ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT),
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [1, 7, 11, 666],                                          # Wrong extras
        False
    ),
]

@pytest.mark.parametrize(
    'system, secret, public, extras_1, extras_2, _bool',
    _system_secret_public_extras__bool
)
def test_schnorr_protocol(system, secret, public, extras_1, extras_2, _bool):

    proof = system.schnorr_proof(secret, public, *extras_1)
    valid = system.schnorr_verify(proof, public, *extras_2)

    assert valid is _bool


_system_secret_public = [
    (
        ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT),
        _2048_KEY,
        _2048_PUBLIC
    ),
    (
        ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT),
        _4096_KEY,
        _4096_PUBLIC
    )
]

@pytest.mark.parametrize('system, secret, public', _system_secret_public)
def test_non_random_keygen(system, secret, public):

    private_key, public_key, proof = system.keygen(private_key=secret, schnorr=True)
    valid = system.schnorr_verify(proof, public_key)

    assert private_key == secret and public_key == public and valid


_system = [
    ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT),
    ModPrimeCrypto(modulus=_4096_PRIME, element=_4096_ELEMENT)
]

@pytest.mark.parametrize('system', _system)
def test_random_keygen(system):

    public_key, proof = system.keygen(schnorr=True)[1:]
    valid = system.schnorr_verify(proof, public_key)

    assert valid
