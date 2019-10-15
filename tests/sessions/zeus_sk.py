"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep
from copy import deepcopy

from zeus_core.mixnets import Zeus_sk
from zeus_core.mixnets.zeus_sk.mixnet import MixNotVerifiedError
from zeus_core.utils.binutils import bit_iterator
from zeus_core.utils.random import random_integer

from tests.constants import (_2048_SYSTEM, _4096_SYSTEM, RES11_SYSTEM,
    _2048_ELECTION_KEY, _4096_ELECTION_KEY, RES11_ELECTION_KEY)

def _exit(message, code=1):
    print(message)
    print('\nMixing session incomplete: CHECK FAILED\n')
    sys.exit(code)

def _make_ciphers(cryptosys, nr_ciphers=40):
    random_element = cryptosys.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

def _make_ciphers_to_mix(cryptosys, nr_rounds=12):
    params = cryptosys.parameters()
    ciphers_to_mix = {
        'modulus': params['modulus'],
        'order': params['order'],
        'generator': params['generator'],
        'public': cryptosys.get_key_value(cryptosys._get_public(cryptosys.keygen())),
        'original_ciphers': [],
        'mixed_ciphers': _make_ciphers(cryptosys),
        'cipher_collections': []
    }
    return ciphers_to_mix

ROUNDS = 100
MIXES = 20

if __name__=='__main__':

    print('\n----------------- Zeus SK Mixing Test Session -----------------\n')
    sleep(1)

    cryptosys = RES11_SYSTEM # _2048_SYSTEM # _4096_SYSTEM
    election_key = RES11_ELECTION_KEY # _2048_ELECTION_KEY # _4096_ELECTION_KEY

    mixnet = Zeus_sk({
        'cryptosys': cryptosys,
        'nr_rounds': ROUNDS,
        'nr_mixes': MIXES
    }, election_key=election_key)

    ciphers = _make_ciphers(cryptosys)

    # Synchronous Mixing
    print('Mixing synchronously')
    sleep(1)
    ciphers_to_mix = _make_ciphers_to_mix(cryptosys, ROUNDS)
    try:
        cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_parallel=0)
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

    print()

    corrupt = deepcopy(cipher_mix)
    del corrupt['public']
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Malformed cipher mix successfully detected')
    else:
        _exit(' - Malformed cipher mix failed to be detected')

    corrupt = deepcopy(cipher_mix)
    del corrupt['proof']['cipher_collections']
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Malformed mix proof successfully detected')
    else:
        _exit(' - Malformed mix proof failed to be detected')

    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['challenge'] += '0'
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Invalid challenge successfully detected')
    else:
        _exit(' - Invalid challenge failed to be detected')

    try:
        lower_bound = ROUNDS + 1
        mixnet.verify_cipher_mix(cipher_mix, min_rounds=lower_bound)
    except MixNotVerifiedError:
        print(' + Wrong lower bound successfully detected')
    else:
        _exit(' - Wrong lower bound failed to be detected')

    corrupt = deepcopy(cipher_mix)
    corrupt['proof']['offset_collections'] += [0]
    try:
        mixnet.verify_cipher_mix(corrupt, nr_parallel=0)
    except MixNotVerifiedError:
        print(' + Wrong collection length successfully detected')
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
    else:
        _exit(' - Unverified round failed to be detected')


    # # Asynchronous Mixing
    # print('\nMixing asynchronously\n')
    # sleep(1)
    # ciphers_to_mix = _make_ciphers_to_mix(cryptosys)
    # try:
    #     cipher_mix = mixnet.mix_ciphers(ciphers_to_mix, nr_parallel=2)
    # except:
    #     _exit(' - Async mixing failed to be performed')
    # else:
    #     print(' + Async mixing successfully performed')


    print('\nMixing session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
