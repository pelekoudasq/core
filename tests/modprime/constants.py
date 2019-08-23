"""
Contains constants for testing
"""

from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE


# Algebraic objects

modulus = 11

Q_RES_11_GROUP = ModPrimeSubgroup(modulus, 2)  # quadratic residues mod 11

_00_ = ModPrimeElement(0, modulus)
_01_ = ModPrimeElement(1, modulus)
_02_ = ModPrimeElement(2, modulus)
_03_ = ModPrimeElement(3, modulus)
_04_ = ModPrimeElement(4, modulus)
_05_ = ModPrimeElement(5, modulus)
_06_ = ModPrimeElement(6, modulus)
_07_ = ModPrimeElement(7, modulus)
_08_ = ModPrimeElement(8, modulus)
_09_ = ModPrimeElement(9, modulus)
_10_ = ModPrimeElement(10, modulus)


# Cryptosystems

_2048_SYSTEM = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(modulus=_4096_PRIME, primitive=_4096_PRIMITIVE)

Q_RES_11_SYSTEM = ModPrimeCrypto(modulus=11, primitive=2, allow_weakness=True)

# Election objects

choices = [
    'Party-A: 0-2, 0',
    'Party-A: Candidate-0000',
    'Party-B: generator0-2, 1',
    'Party-B:l Candidate-0001'
    'Party-C:l Candidate-0x00']
