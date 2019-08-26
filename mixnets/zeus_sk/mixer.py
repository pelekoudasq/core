from itertools import chain
from hashlib import sha256
from Crypto import Random

from utils.teller import _teller
from utils.binutils import bit_iterator
from utils.async import AsyncController

ALPHA = 0
BETA  = 1

MIN_MIX_ROUNDS = 1

def compute_mix_challenge(cipher_mix):
    """
    :type cipher_mix: dict
    :rtype: str
    """
    hasher = sha256()
    update = hasher.update

    update(('%x' % cipher_mix['modulus']).encode('utf-8'))
    update(('%x' % cipher_mix['order']).encode('utf-8'))
    update(('%x' % cipher_mix['generator']).encode('utf-8'))
    update(('%x' % cipher_mix['public'].to_integer()).encode('utf-8'))

    original_ciphers = cipher_mix['original_ciphers']
    mixed_ciphers = cipher_mix['mixed_ciphers']
    cipher_collections = cipher_mix['proof']['cipher_collections']

    ciphers = chain(original_ciphers, mixed_ciphers, *cipher_collections)
    for cipher in ciphers:
        update(('%x' % cipher[ALPHA].to_integer()).encode('utf-8'))
        update(('%x' % cipher[BETA].to_integer()).encode('utf-8'))

    challenge = hasher.hexdigest()
    return challenge

from utils.random import random_permutation

def shuffle_ciphers(ciphers, public, encrypt_func,
            teller=None, report_thres=128, async_channel=None):
    """
    Reencrypts the provided `ciphers` under the given key `public` and returns a random
    permutation of the new ciphers, along with the list of indices encoding this
    permutation and the randomnesses used for re-encryption in the original order

    :type ciphers: list[(ModPrimeElement, ModPrimeElement)]
    :type public: ModPrimeElement
    :type encrypt_func:
    :rtype: (list[(ModPrimeElement, ModPrimeElement)], list[int], list[mpz])
    """
    nr_ciphers = len(ciphers)
    mixed_offsets = random_permutation(nr_ciphers)

    mixed_ciphers = [None] * nr_ciphers
    mixed_randoms = [None] * nr_ciphers
    count = 0
    for i in range(nr_ciphers):

        alpha, beta = ciphers[i]
        alpha, beta, secret = encrypt_func(alpha, beta, public, get_secret=True)

        mixed_randoms[i] = secret
        j = mixed_offsets[i]
        mixed_ciphers[j] = (alpha, beta)

        count += 1
        if teller:
            teller.advance(count)
        if async_channel:
            async_channel.send_shared(count, wait=1)
        if count >= report_thres:
            count = 0

    return mixed_ciphers, mixed_offsets, mixed_randoms

def mix_ciphers(ciphers_to_mix, encrypt_func, nr_rounds=MIN_MIX_ROUNDS, teller=_teller, nr_parallel=0): #
    """
    :type ciphers_to_mix: dict
    :type encrypt_func:
    :rtype: dict
    """
    modulus = ciphers_to_mix['modulus']
    order = ciphers_to_mix['order']
    generator = ciphers_to_mix['generator']

    public = ciphers_to_mix['public']

    original_ciphers = ciphers_to_mix['mixed_ciphers']
    nr_ciphers = len(original_ciphers)

    if nr_parallel > 0:
        Random.atfork()
        _async = AsyncController(parallel=nr_parallel)
        async_shuffle_ciphers = _async.make_async(shuffle_ciphers)              #

    teller.task('Mixing %d ciphers for %d rounds' % (nr_ciphers, nr_rounds))

    cipher_mix = {}
    cipher_mix['modulus'] = modulus
    cipher_mix['order'] = order
    cipher_mix['generator'] = generator
    cipher_mix['public'] = public
    cipher_mix['original_ciphers'] = original_ciphers

    with teller.task('Producing final mixed ciphers'):
        mixed_ciphers, mixed_offsets, mixed_randoms = \
            shuffle_ciphers(original_ciphers, public, encrypt_func, teller=teller)            #
        cipher_mix['mixed_ciphers'] = mixed_ciphers

    total = nr_ciphers * nr_rounds
    with teller.task('Producing ciphers for proof', total=total):
        if nr_parallel > 0:
            #
            #
            #
            pass
        else:
            collections = [shuffle_ciphers(original_ciphers, public, encrypt_func, teller=teller)
                for _ in range(nr_rounds)]

        unzipped = [list(x) for x in zip(*collections)]
        cipher_collections, offset_collections, random_collections = unzipped
        cipher_mix['proof'] = {
            'cipher_collections': cipher_collections,
            'offset_collections': offset_collections,
            'random_collections': random_collections
        }

    with teller.task('Producing cryptographic hash challenge'):
        challenge = compute_mix_challenge(cipher_mix)
        cipher_mix['proof']['challenge'] = challenge

    bits = bit_iterator(int(challenge, 16))
    with teller.task('Answering according to challenge', total=nr_rounds):
        for i, bit in zip(range(nr_rounds), bits):
            ciphers = cipher_collections[i]
            offsets = offset_collections[i]
            randoms = random_collections[i]

            if bit == 0:
                pass              # Do nothing, just publish offsets and randoms
            elif bit == 1:
                new_offsets = [None] * nr_ciphers
                new_randoms = [None] * nr_ciphers

                for j in range(nr_ciphers):
                    k = offsets[j]
                    new_offsets[k] = mixed_offsets[j]
                    new_randoms[k] = (mixed_randoms[j] - randoms[j]) % order

                offset_collections[i] = new_offsets
                random_collections[i] = new_randoms

                del offsets, randoms
            else:
                e = 'This should be impossible. Something is broken'
                raise AssertionError(e)
            teller.advance()

    teller.finish('Mixing')
    return cipher_mix
