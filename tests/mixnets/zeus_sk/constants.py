"""
Contains constants for testing
"""

from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE


# Cryptosystems

Q_RES_11_SYSTEM = ModPrimeCrypto(11, 2, allow_weakness=True)

_2048_SYSTEM = ModPrimeCrypto(_2048_PRIME, _2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(_4096_PRIME, _4096_PRIMITIVE)


# Algebraic objects

Q_RES_11_GROUP = Q_RES_11_SYSTEM.group              # quadratic residues mod 11

_00_ = ModPrimeElement(0, 11)
_01_ = ModPrimeElement(1, 11)
_02_ = ModPrimeElement(2, 11)
_03_ = ModPrimeElement(3, 11)
_04_ = ModPrimeElement(4, 11)
_05_ = ModPrimeElement(5, 11)
_06_ = ModPrimeElement(6, 11)
_07_ = ModPrimeElement(7, 11)
_08_ = ModPrimeElement(8, 11)
_09_ = ModPrimeElement(9, 11)
_10_ = ModPrimeElement(10, 11)


# Election objects

_2048_ELECTION_KEY = _2048_SYSTEM.group.random_element()
_4096_ELECTION_KEY = _4096_SYSTEM.group.random_element()

choices = [
    'Party-A: 0-2, 0',
    'Party-A: Candidate-0000',
    'Party-B: generator0-2, 1',
    'Party-B:l Candidate-0001'
    'Party-C:l Candidate-0x00']
