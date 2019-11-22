"""
"""

from zeus_core.crypto import ModPrimeCrypto
from zeus_core.crypto.constants import (
                        _2048_PRIME, _2048_PRIMITIVE,
                        _4096_PRIME, _4096_PRIMITIVE)
from zeus_core.mixnets import Zeus_sk

config_1 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": _2048_PRIME,
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_sk,
        "config": {
            "nr_rounds": 2,
            "nr_mixes": 2
        }
    },
    "zeus_secret": "tests/election/emulators/zeus-secret.json",
    "trustees": "tests/election/emulators/trustees.json",
    "candidates": "tests/election/emulators/candidates.json",
    "voters": "tests/election/emulators/voters.json",
}
