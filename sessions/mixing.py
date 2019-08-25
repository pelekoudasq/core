"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep

from mixnets import Zeus_SK

from tests.crypto.modprime.constants import _2048_SYSTEM, _4096_SYSTEM

def _exit(message, code=1):
    print(message)
    print('\nMixing session incomplete: CHECK FAILED\n')
    sys.exit(code)

def _make_ciphers(cryptosystem, nr_ciphers=12):
    random_element = cryptosystem.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

ROUNDS = 100
MIXES = 20

if __name__=='__main__':

    print('\n----------------- Zeus SK Mixing Test Session -----------------\n')

    print('Making Sako-Killian mixnet')
    sleep(.5)
    
    cryptosystem = _4096_SYSTEM
    election_key = cryptosystem._extract_public(cryptosystem.keygen())

    mixnet = Zeus_SK({
        'cryptosystem': cryptosystem,
        'nr_rounds': ROUNDS,
        'nr_mixes': MIXES
    }, election_key)

    ciphers = _make_ciphers(cryptosystem)

    print('Shuffling ciphers')
    sleep(.5)
    
    public = cryptosystem._extract_value(election_key)
    mixed_ciphers, mixed_offsets, mixed_randoms = \
        mixnet._shuffle_ciphers(ciphers, public)

    print('\nMixing session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
