"""
"""

from zeus_core.crypto import ModPrimeCrypto
from zeus_core.crypto.constants import (
                        _2048_PRIME, _2048_PRIMITIVE,
                        _4096_PRIME, _4096_PRIMITIVE)
from zeus_core.mixnets import Zeus_sk

config_1 = {
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
    'zeus_private_key': 4269531922782610866888884240036589418998030134824377934958106824978064009038594793579045996761929827344206371602325044130263448507165982122419847957243192346730609699869538976706604539210499344872956884161374164249946836053499662427715858538669475898360095569764911071331353490584718444881146697278936641164880522005560944332459043993468386572415294516204480879630466476408303514126114646460627577106574186883242839892888383210840327146350225553865716191372491288569061296220669971405571406353413109758918026361634649568581616902980895342970884823962503066995006060492237263550641450990283455211931072774385642006197,
    'trustees_file': 'tests/election/emulators/trustee-publics.json',
    'candidates_file': 'tests/election/emulators/candidates.json',
}
