"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep
from copy import deepcopy

from mixnets import Zeus_SK
from mixnets.zeus_sk.mixnet import MixNotVerifiedError
from utils.binutils import bit_iterator
from utils.random import random_integer

from tests.constants import (_2048_SYSTEM, _4096_SYSTEM, RES11_SYSTEM,
    _2048_ELECTION_KEY, _4096_ELECTION_KEY, RES11_ELECTION_KEY)

def _exit(message, code=1):
    print(message)
    print('\nMixing session incomplete: CHECK FAILED\n')
    sys.exit(code)

def _make_ciphers(cryptosystem, nr_ciphers=40):
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

    cryptosystem = RES11_SYSTEM # _2048_SYSTEM # _4096_SYSTEM
    election_key = RES11_ELECTION_KEY # _2048_ELECTION_KEY # _4096_ELECTION_KEY

    mixnet = Zeus_SK({
        'cryptosystem': cryptosystem,
        'nr_rounds': ROUNDS,
        'nr_mixes': MIXES
    }, election_key)

    ciphers = _make_ciphers(cryptosystem)

    # Synchronous Mixing
    print('Mixing synchronously')
    sleep(1)
    ciphers_to_mix = _make_ciphers_to_mix(cryptosystem)
    try:
        cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_rounds=12, nr_parallel=0)
    except:
        _exit(' - Sync mixing failed to be performed')
    else:
        print(' + Sync mixing successfully performed')

    # Synchronous Verification

    print('\nPerforming synchronous verifications\n')
    sleep(1)
    try:
        mixnet.verify_cipher_mix(cipher_mix, nr_parallel=0)
    except:
        _exit(' - Sync verification failed to be performed')
    else:
        print(' + Sync verification successfully performed')

    # sys.stdout.write('\n')
    print()

    corrupt = deepcopy(cipher_mix)
    del corrupt['public']
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Malformed cipher mix successfully detected')
    except:
        _exit(' - Malformed cipher mix failed to be detected')
    else:
        _exit(' - Malformed cipher mix failed to be detected')

    corrupt = deepcopy(cipher_mix)
    del corrupt['proof']['cipher_collections']
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Malformed mix proof successfully detected')
    except:
        _exit(' - Malformed mix proof failed to be detected')
    else:
        _exit(' - Malformed mix proof failed to be detected')

    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['challenge'] += '0'
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Invalid challenge successfully detected')
    except:
        _exit(' - Invalid challenge failed to be detected')
    else:
        _exit(' - Invalid challenge failed to be detected')

    try:
        lower_bound = ROUNDS - 1
        mixnet.verify_cipher_mix(cipher_mix, min_rounds=lower_bound)
    except MixNotVerifiedError:
        print(' + Wrong lower bound successfully detected')
    except:
        _exit(' - Wrong lower bound failed to be detected')
    else:
        _exit(' - Wrong lower bound failed to be detected')

    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['offset_collections'] += [0]
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Wrong collection length successfully detected')
    except:
        _exit(' - Wrong collection length failed to be detected')
    else:
        _exit(' - Wrong collection length failed to be detected')

    corrupt = deepcopy(cipher_mix)
    bit = next(bit_iterator(int(corrupt['proof']['challenge'], 16)))
    if bit == 0:
        preimages = corrupt['original_ciphers']
        images = corrupt['proof']['cipher_collections'][0]
    else:
        preimages = corrupt['proof']['cipher_collections'][0]
        images = corrupt['mixed_ciphers']
    images[0][0].reduce_value()
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Unverified round successfully detected')
    except:
        _exit(' - Unverified round failed to be detected')
    else:
        _exit(' - Unverified round failed to be detected')


    # # Asynchronous Mixing
    # print('\nMixing asynchronously\n')
    # sleep(1)
    # ciphers_to_mix = _make_ciphers_to_mix(cryptosystem)
    # try:
    #     cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_rounds=12, nr_parallel=2)
    # except:
    #     _exit(' - Async mixing failed to be performed')
    # else:
    #     print(' + Async mixing successfully performed')


    print('\nMixing session complete: ALL CHECKS PASSED\n')
    sys.exit(0)