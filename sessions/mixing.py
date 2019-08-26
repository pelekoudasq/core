"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep

from mixnets import Zeus_SK

from tests.constants import _2048_SYSTEM, _4096_SYSTEM, RES11_SYSTEM

def _exit(message, code=1):
    print(message)
    print('\nMixing session incomplete: CHECK FAILED\n')
    sys.exit(code)

def _make_ciphers(cryptosystem, nr_ciphers=12):
    random_element = cryptosystem.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

def _make_ciphers_to_mix(cryptosystem):
    params = cryptosystem.parameters
    ciphers_to_mix = {
        'modulus': params['modulus'],
        'order': params['order'],
        'generator': params['generator'],
        'public': cryptosystem._extract_value(cryptosystem._extract_public(cryptosystem.keygen())),
        'original_ciphers': [],
        'mixed_ciphers': _make_ciphers(cryptosystem),
        'cipher_collections': []
    }
    return ciphers_to_mix

ROUNDS = 100
MIXES = 20

if __name__=='__main__':

    print('\n----------------- Zeus SK Mixing Test Session -----------------\n')

    print('Making Sako-Killian mixnet')
    sleep(.5)

    cryptosystem = RES11_SYSTEM #_4096_SYSTEM
    election_key = cryptosystem._extract_public(cryptosystem.keygen())

    mixnet = Zeus_SK({
        'cryptosystem': cryptosystem,
        'nr_rounds': ROUNDS,
        'nr_mixes': MIXES
    }, election_key)

    ciphers = _make_ciphers(cryptosystem)

    # Shuffling
    from mixnets.zeus_sk.mixer import shuffle_ciphers

    # print('Shuffling ciphers')
    # sleep(.5)
    # public = cryptosystem._extract_value(election_key)
    # mixed_ciphers, mixed_offsets, mixed_randoms = \
    #     mixnet._shuffle_ciphers(ciphers, public)
    # # mixed_ciphers, mixed_offsets, mixed_randoms = \
    # #     shuffle_ciphers(ciphers, public, mixnet._reencrypt)

    # Mixing
    from mixnets.zeus_sk.mixer import mix_ciphers
    ciphers_to_mix = _make_ciphers_to_mix(cryptosystem)
    print(ciphers_to_mix)
    cipher_mix = mix_ciphers(ciphers_to_mix, mixnet._reencrypt)
    print(cipher_mix)



    print('\nMixing session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
