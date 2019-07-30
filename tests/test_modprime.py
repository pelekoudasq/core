import pytest
from math import floor

from crypto.algebra import (_mul, _divmod, _mod, _pow, _inv, isresidue,
                            make_cryptosys, make_schnorr_proof, make_schnorr_verify)
from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC,
                              _4096_PRIME, _4096_ELEMENT, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC)
from crypto.exceptions import (WrongConfigsError, WrongCryptoError)


from crypto.modprime import ModPrimeCrypto


# def test_test():
#     cryptosys = ModPrimeCrypto(_4096_PRIME, 2, _4096_ELEMENT)
#     assert True
