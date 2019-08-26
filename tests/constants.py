"""
Contains constants for testing
"""

from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE
from mixnets import Zeus_SK


# Algebraic objects

RES11_GROUP = ModPrimeSubgroup(11, 2)             # quadratic residues mod 11

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


# Cryptosystems

RES11_SYSTEM = ModPrimeCrypto(11, 2, allow_weakness=True)
_2048_SYSTEM = ModPrimeCrypto(_2048_PRIME, _2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(_4096_PRIME, _4096_PRIMITIVE)


# Election keys

RES11_ELECTION_KEY = RES11_SYSTEM.group.random_element()
_2048_ELECTION_KEY = _2048_SYSTEM.group.random_element()
_4096_ELECTION_KEY = _4096_SYSTEM.group.random_element()


# Sako-Killian Mixnets

RES11_ZEUS_SK = Zeus_SK({
    'cryptosystem': RES11_SYSTEM,
    'nr_rounds': 100,
    'nr_mixes': 20
}, RES11_ELECTION_KEY)

_2048_ZEUS_SK = Zeus_SK({
    'cryptosystem': _2048_SYSTEM,
    'nr_rounds': 100,
    'nr_mixes': 20
}, _2048_ELECTION_KEY)

_4096_ZEUS_SK = Zeus_SK({
    'cryptosystem': _4096_SYSTEM,
    'nr_rounds': 100,
    'nr_mixes': 20
}, _4096_ELECTION_KEY)


# Verificatum mixnets

#

# Candidates

choices = [
    'Party-A: 0-2, 0',
    'Party-A: Candidate-0000',
    'Party-B: generator0-2, 1',
    'Party-B:l Candidate-0001'
    'Party-C:l Candidate-0x00']
