"""
"""

from zeus_core.crypto import ModPrimeCrypto
from zeus_core.crypto.constants import (
                        _2048_PRIME, _2048_PRIMITIVE,
                        _4096_PRIME, _4096_PRIMITIVE)
from zeus_core.mixnets import Zeus_SK


config_1 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": _2048_PRIME,
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
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


config_2 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": 15,                   # WrongCryptoError: Provided modulus is not an odd prime
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
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

config_3 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
        "modulus": 17,                  # WrongCryptoError: Provided modulus is not an odd prime
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
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

config_4 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": _2048_PRIME,
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
        "config": {
            # "nr_rounds": ...,             # WrongMixnetError: Malformed parameters for Zeus SK mixnet
            "nr_mixes": 2
        }
    },
    "zeus_secret": "tests/election/emulators/zeus-secret.json",
    "trustees": "tests/election/emulators/trustees.json",
    "candidates": "tests/election/emulators/candidates.json",
    "voters": "tests/election/emulators/voters.json",
}

config_5 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": _2048_PRIME,
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
        "config": {
            "nr_rounds": 2,
            "nr_mixes": 2
        }
    },
    "zeus_secret": "tests/election/emulators/zeus-secret.json",
    "trustees": "tests/election/emulators/trustees.json",
    "candidates": "tests/election/emulators/dupl_candidates.json",  # InvalidCandidateError: Duplicate candidate detected
    "voters": "tests/election/emulators/voters.json",
}

config_6 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": _2048_PRIME,
            "primitive": _2048_PRIMITIVE
        }
    },
    "mixnet": {
        "cls": Zeus_SK,
        "config": {
            "nr_rounds": 2,
            "nr_mixes": 2
        }
    },
    "zeus_secret": "tests/election/emulators/zeus-secret.json",
    "trustees": "tests/election/emulators/trustees.json",
    "candidates": "tests/election/emulators/candidates.json",
    "voters": "tests/election/emulators/dupl_voters.json",          # InvalidVoterError: Duplicate voter detected
}
