from itertools import chain
from hashlib import sha256
from Crypto import Random

from utils.random import random_permutation

ALPHA = 0
BETA  = 1

class RoundNotVerifiedError(BaseException):
    """
    Raised when a mix round fails to be verified
    """
    pass

def _raise_RoundNotVerifiedError(round_nr, cipher_nr, bit):
    """
    :type round_nr: int
    :type cipher_nr: int
    :type bit: int
    """
    e = 'MIXING VERIFICATION FAILED AT ROUND %d CIPHER %d bit %d' % (
            round_nr, cipher_nr, bit)
    raise RoundNotVerifiedError(e)


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


def shuffle_ciphers(ciphers, public, encrypt_func, teller=None,
            report_thres=128, async_channel=None):
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


def verify_mix_round(round_nr, bit, original_ciphers, mixed_ciphers,
        ciphers, offsets, randoms, encrypt_func, public,
        teller=None, report_thres=128, async_channel=None):
    """
    Returns True if the round is successfully verified, otherwise raises
    `RoundNotVerifiedError`

    :type round_nr: int
    :type bit: int
    :type original_ciphers: list[(ModPrimeElement, ModPrimeElement)]
    :type mixed_ciphers: list[(ModPrimeElement, ModPrimeElement)]
    :type ciphers: list[(ModPrimeElement, ModPrimeElement)]
    :type offsets: list[mpz]
    :type randoms: list[mpz]
    :type encrypt_func:
    :type public: ModPrimeElement
    :type teller:
    :type report_thres: int
    :type async_channel:
    :rtype: bool
    """
    nr_ciphers = len(original_ciphers)

    if bit == 0:
        preimages = original_ciphers
        images = ciphers
    elif bit == 1:
        preimages = ciphers
        images = mixed_ciphers
    else:
        e = 'This should be impossible. Something is broken'
        raise AssertionError(e)

    count = 0
    for j in range(nr_ciphers):
        preimage = preimages[j]
        offset = offsets[j]
        random = randoms[j]

        alpha = preimage[ALPHA]
        beta = preimage[BETA]
        new_alpha, new_beta = encrypt_func(alpha, beta, public, randomness=random)

        image = images[offset]
        if new_alpha != image[ALPHA] or new_beta != image[BETA]:
            _raise_RoundNotVerifiedError(round_nr=round_nr, cipher_nr=j, bit=bit)

        count += 1
        if count >= report_thres:
            if async_channel:
                async_channel.send_shared(count)
            if teller:
                teller.advance(count)
            count = 0

    if count:
        if async_channel:
            async_channel.send_shared(count)
        if teller:
            teller.advance(count)

    return True
