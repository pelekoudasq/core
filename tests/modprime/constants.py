from crypto.modprime import ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE

_2048_SYSTEM = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(modulus=_4096_PRIME, primitive=_4096_PRIMITIVE)

choices = [
    'Party-A: 0-2, 0',
    'Party-A: Candidate-0000',
    'Party-B: generator0-2, 1',
    'Party-B:l Candidate-0001'
    'Party-C:l Candidate-0x00']
