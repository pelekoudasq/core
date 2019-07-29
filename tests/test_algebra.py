import pytest
from math import floor

from crypto.algebra import (_mul, _divmod, _mod, _pow, _inv, isresidue,
                            make_cryptosys, make_schnorr_proof, make_schnorr_verify)
from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC,
                              _4096_PRIME, _4096_ELEMENT, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC)
from crypto.exceptions import (WrongConfigsError, WrongCryptoError)


# Elementary INTEGER operations


_2_ples_with_zeros = [(m, n) for m in range(0, 5) for n in range(0, 5)]

@pytest.mark.parametrize('m, n', _2_ples_with_zeros)
def test__mul(m, n):
    assert _mul(m, n) == m * n


_2_ples_without_zeroes = [(m, n) for m in range(0, 5) for n in range(1, 5)]

@pytest.mark.parametrize('m, n', _2_ples_without_zeroes)
def test__divmod(m, n):
    assert _divmod(m, n) == (floor(m / n), m % n)

@pytest.mark.parametrize('m, n', _2_ples_without_zeroes)
def test__mod(m, n):
    assert _mod(m, n) == m % n


_3_ples = [(m, n, r) for m in range(0, 5) for n in range(0, 5) for r in range(1, m ** n)]

@pytest.mark.parametrize('m, n, r', _3_ples)
def test__pow(m, n, r):
    assert _pow(m, n, r) == m ** n % r


modular_inverses = [
    (1, 1, 2),
    (1, 1, 3), (2, 2, 3),
    (1, 1, 4), (3, 3, 4),
    (1, 1, 5), (2, 3, 5), (3, 2, 5), (4, 4, 5),
    (1, 1, 6), (5, 5, 6),
    (1, 1, 7), (2, 4, 7), (3, 5, 7), (4, 2, 7), (5, 3, 7), (6, 6, 7)
]

@pytest.mark.parametrize('x, y, r', modular_inverses)
def test__inv(x, y, r):
    assert _inv(x, r) == y


# Test powering inside Z^*_p for large p's

prime_and_element = [(_2048_PRIME, _2048_ELEMENT), (_4096_PRIME, _4096_ELEMENT)]

@pytest.mark.parametrize('p, a', prime_and_element)
def test_multiplicative_group_order(p, a):
    assert _pow(a, p - 1, p) == 1

@pytest.mark.parametrize('p, a', prime_and_element)
def test_multiplicative_subgroup_order(p, a):
    assert _pow(_pow(a, 2, p) , _divmod(p - 1, 2)[0], p) == 1


# Test modular residues

_modular_residues = [

    # (x, q, p), q = (p - 1)/r when checking for r-residues x mod p > 2

    # quadratic

    (1, 1, 3, True),

    (1, 2, 5, True), (2, 2, 5, False), (3, 2, 5, False), (4, 2, 5, True),

    (1, 3, 7, True), (2, 3, 7, True), (3, 3, 7, False), (4, 3, 7, True),
    (5, 3, 7, False), (6, 3, 7, False),

    (1, 5, 11, True), (2, 5, 11, False), (3, 5, 11, True),  (4, 5, 11, True),
    (5, 5, 11, True), (6, 5, 11, False), (7, 5, 11, False), (8, 5, 11, False),
    (9, 5, 11, True), (10, 5, 11, False),

    (_2048_GENERATOR, _2048_ORDER, _2048_PRIME, True),
    (_4096_GENERATOR, _4096_ORDER, _4096_PRIME, True)

    # qubic
    # quatric
]

@pytest.mark.parametrize('x, q, p, _bool', _modular_residues)
def test_isresidue(x, q, p, _bool):
    assert isresidue(x, q, p) is _bool


# Cryptosystem construction

_wrong_config__type = [
    (
        {'anything...'},
        'anything unsupported'
    ),
    (
        {'modulus': 5, 'root_order': 2, 'element':3, 'extra':0}, # extra field
        'integer'
    ),
    (
        {'modulus': 5, 'root_order': 2},                         # missing field
        'integer'
    ),
    (
        {'modulus': 5, 'wrong_field': 2, 'element':3},           # wrong field
        'integer'
    ),
]

@pytest.mark.parametrize('config, _type', _wrong_config__type)
def test_WrongConfigsError(config, _type):
    with pytest.raises(WrongConfigsError):
        make_cryptosys(config, _type)

_configs_and_parameters = [
    (
        _2048_PRIME,
        2,
        _2048_ELEMENT,
        _2048_GENERATOR,
        _2048_ORDER
    ),
    (
        _4096_PRIME,
        2,
        _4096_ELEMENT,
        _4096_GENERATOR,
        _4096_ORDER
    )
]

@pytest.mark.parametrize('modulus, root_order, element, generator, order', _configs_and_parameters)
def test_make_cryptosys(modulus, root_order, element, generator, order):

    cryptosys = make_cryptosys(config={
        'modulus': modulus,
        'root_order': root_order,
        'element': element
    }, _type='integer')

    assert cryptosys == {
        'parameters': {
            'modulus': modulus,
            'generator': generator,
            'order': order
        },
        'type': 'integer'
    }


_cryptosys_secret_public_extras__bool = [
    (
        {
            'parameters': {
                'modulus': _2048_PRIME,
                'generator': _2048_GENERATOR,
                'order': _2048_ORDER
            },
            'type': 'integer'
        },
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
    (
        {
            'parameters': {
                'modulus': _2048_PRIME,
                'generator': _2048_GENERATOR,
                'order': _2048_ORDER,
            },
            'type': 'integer'
        },
        12345,                                                 # Wrong logarithm
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        False
    ),
    (
        {
            'parameters': {
                'modulus': _2048_PRIME,
                'generator': _2048_GENERATOR,
                'order': _2048_ORDER,
            },
            'type': 'integer'
        },
        _2048_KEY,
        _2048_PUBLIC,
        [0, 7, 11, 666],
        [1, 7, 11, 666],                                          # Wrong extras
        False
    ),
    (
        {
            'parameters': {
                'modulus': _4096_PRIME,
                'generator': _4096_GENERATOR,
                'order': _4096_ORDER
            },
            'type': 'integer'
        },
        _4096_KEY,
        _4096_PUBLIC,
        [0, 7, 11, 666],
        [0, 7, 11, 666],
        True
    ),
]

@pytest.mark.parametrize(
    'cryptosys, secret, public, extras_1, extras_2, _bool',
    _cryptosys_secret_public_extras__bool
)
def test_schnorr_protocol(cryptosys, secret, public, extras_1, extras_2, _bool):

    schnorr_proof = make_schnorr_proof(cryptosys)
    schnorr_verify = make_schnorr_verify(cryptosys)

    import json
    print(json.dumps(cryptosys, indent=4, sort_keys=True))

    proof = schnorr_proof(secret, public, *extras_1)
    valid = schnorr_verify(proof, public, *extras_2)
    print(valid)

    assert valid is _bool
