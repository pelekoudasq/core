from zeus_elections.elections import ZeusCoreElection

from crypto import ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE
from mixnets import Zeus_sk

if __name__ == '__main__':
    ZeusCoreElection(
        config={
            'crypto': {
                'cls': ModPrimeCrypto,
                'config': {
                    'modulus': _2048_PRIME,
                    'primitive': _2048_PRIMITIVE
                }
            },
            'mixnet': {
                'cls': Zeus_sk,
                'config': {
                    'nr_rounds': 2,
                    'nr_mixes': 2
                }
            },
            'zeus_private_key': None,
            'nr_parallel': 0
        },
        debug=True).run()
