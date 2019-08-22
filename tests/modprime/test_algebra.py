import pytest

from gmpy2 import mpz

from crypto.constants import (_2048_PRIME, _2048_ORDER, _2048_GENERATOR, _2048_PRIMITIVE,
                              _4096_PRIME, _4096_ORDER, _4096_GENERATOR, _4096_PRIMITIVE)
from crypto.exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto


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
