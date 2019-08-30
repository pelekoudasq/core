import pytest
from gmpy2 import mpz

from crypto.constants import (_2048_PRIME, _2048_ORDER, _2048_GENERATOR, _2048_PRIMITIVE,
                              _4096_PRIME, _4096_ORDER, _4096_GENERATOR, _4096_PRIMITIVE)
from crypto.exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto

from tests.constants import (RES11_GROUP,
    _00_, _01_, _02_, _03_, _04_, _05_, _06_, _07_, _08_, _09_, _10_)


__original__inverse__modulus = [
    (1, 1, 2),
    (1, 1, 3), (2, 2, 3),
    (1, 1, 4), (3, 3, 4),
    (1, 1, 5), (2, 3, 5), (3, 2, 5), (4, 4, 5),
    (1, 1, 6), (5, 5, 6),
    (1, 1, 7), (2, 4, 7), (3, 5, 7), (4, 2, 7), (5, 3, 7), (6, 6, 7)
]

@pytest.mark.parametrize('original, inverse, modulus', __original__inverse__modulus)
def test_modular_inversion(original, inverse, modulus):

    original = ModPrimeElement(mpz(original), mpz(modulus))
    assert original.inverse.value == inverse

__AlgebraError__modulus__root_order = [
    (0, 0),
    (1, 0), (1, 1),
    (2, 0), (2, 1), (2, 2),
    (3, 0), (3, 3),
    (4, 0), (4, 1), (4, 2), (4, 3), (4, 4),
    (5, 0), (5, 3), (5, 5),
    (7, 0), (7, 4), (7, 5), (7, 7),
    (11, 0), (11, 3), (11, 4), (11, 6), (11, 7), (11, 8), (11, 9), (11, 11)
]

@pytest.mark.parametrize('modulus, root_order', __AlgebraError__modulus__root_order)
def test_AlgebraError_in_ModPrimeSubgroup_Construction(modulus, root_order):
    with pytest.raises(AlgebraError):
        ModPrimeSubgroup(modulus, root_order)


__modulus__root_order__order = [
    (3, 1, 2), (3, 2, 1),
    (5, 1, 4), (5, 2, 2), (5, 4, 1),
    (7, 1, 6), (7, 2, 3), (7, 3, 2), (7, 6, 1),
    (11, 1, 10), (11, 2, 5), (11, 5, 2), (11, 10, 1),

    (_2048_PRIME, 2, _2048_ORDER), (_2048_PRIME, _2048_ORDER, 2),
    (_4096_PRIME, 2, _4096_ORDER), (_4096_PRIME, _4096_ORDER, 2),
]

@pytest.mark.parametrize('modulus, root_order, order', __modulus__root_order__order)
def test_ModPrimeSubgroup_Construction(modulus, root_order, order):
    group = ModPrimeSubgroup(modulus, root_order)
    assert (group.modulus, group.order) == (modulus, order)


# Full testing of residue property in mod11 context

RES11_GROUP.set_generator(3)

__elements = [_01_, _02_, _03_, _04_, _05_, _06_, _07_, _08_, _09_, _10_]
__residues = [_01_, _03_, _04_, _05_, _09_]


@pytest.mark.parametrize('element', __elements)
def test_contains(element):
    if element in __residues:
        assert RES11_GROUP.contains(element)
    else:
        assert not RES11_GROUP.contains(element)

@pytest.mark.parametrize('element', __elements)
def test_contained_in(element):
    if element in __residues:
        assert element.contained_in(RES11_GROUP)
    else:
        assert not element.contained_in(RES11_GROUP)


__element__decoded = [

    # residues
    (_01_, _00_), (_03_, _02_), (_04_, _03_), (_05_, _04_), (_09_, _08_),

    # non-residues
    (_02_, _08_), (_06_, _04_), (_07_, _03_), (_08_, _02_), (_10_, _00_)
]

@pytest.mark.parametrize('element, decoded', __element__decoded)
def test_decode_with_randomness(element, decoded):
    assert decoded == RES11_GROUP.decode_with_randomness(element)
