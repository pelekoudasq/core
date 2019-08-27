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
    sleep(1)

    cryptosystem = _4096_SYSTEM
    election_key = cryptosystem._extract_public(cryptosystem.keygen())

    mixnet = Zeus_SK({
        'cryptosystem': cryptosystem,
        'nr_rounds': ROUNDS,
        'nr_mixes': MIXES
    }, election_key)

    ciphers = _make_ciphers(cryptosystem)

    # Synchronous Mixing
    print('Doing synchronous mixing')
    sleep(1)
    ciphers_to_mix = _make_ciphers_to_mix(cryptosystem)
    try:
        cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_rounds=12)
    except:
        _exit(' - Sync mixing failed to be performed')
    else:
        print(' + Sync mixing successfully performed')

    # Asynchronous Mixing
    print('\nDoing asynchronous mixing\n')
    sleep(1)
    ciphers_to_mix = _make_ciphers_to_mix(cryptosystem)
    try:
        cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_rounds=12, nr_parallel=2)
    except:
        _exit(' - Async mixing failed to be performed')
    else:
        print(' + Async mixing successfully performed')


    print('\nMixing session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
