"""
Provides ZeusCoreElection config samples for testing
"""

from zeus_core.crypto import ModPrimeCrypto
from zeus_core.crypto.constants import (
                        _2048_PRIME, _2048_PRIMITIVE,
                        _4096_PRIME, _4096_PRIMITIVE)
from zeus_core.mixnets import Zeus_SK


# Correct config: election will successfully finalize

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


# Wrong config: election will abort due to WrongCryptoError:
# Provided modulus is not an odd prime

config_2 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
            "modulus": 15,
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


# Wrong config: election will abort due to WrongCryptoError:
# Provided modulus is not 3 mod 4

config_3 = {
    "crypto": {
        "cls": ModPrimeCrypto,
        "config": {
        "modulus": 17,
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


# Wrong config: election will abort due to WrongMixnetError:
# Malformed parameters for Zeus SK mixnet

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
            # "nr_rounds": ...,
            "nr_mixes": 2
        }
    },
    "zeus_secret": "tests/election/emulators/zeus-secret.json",
    "trustees": "tests/election/emulators/trustees.json",
    "candidates": "tests/election/emulators/candidates.json",
    "voters": "tests/election/emulators/voters.json",
}


# Wrong config: election will abort due to InvalidTrusteeError:
# Detected invalid trustee: ...

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
    "trustees": "tests/election/emulators/inv_trustees.json",
    "candidates": "tests/election/emulators/candidates.json",
    "voters": "tests/election/emulators/voters.json",
}


# Wrong config: election will abort due to InvalidCandidateError:
# Duplicate candidate detected

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
    "candidates": "tests/election/emulators/dupl_candidates.json",
    "voters": "tests/election/emulators/voters.json",
}


# Wrong config: election will abort due to InvalidVoterError:
# Duplicate voter detected

config_7 = {
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
    "voters": "tests/election/emulators/dupl_voters.json",
}
