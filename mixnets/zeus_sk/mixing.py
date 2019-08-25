from itertools import chain
from hashlib import sha256
ALPHA = 0
BETA  = 1

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
    update(('%x' % cipher_mix['public']).encode('utf-8'))

    original_ciphers = cipher_mix['original_ciphers']
    mixed_ciphers = cipher_mix['mixed_ciphers']
    cipher_collections = cipher_mix['proof']['cipher_collections']

    ciphers = chain(original_ciphers, mixed_ciphers, *cipher_collections)
    for cipher in ciphers:
        update(('%x' % cipher[ALPHA]).encode('utf-8'))
        update(('%x' % cipher[BETA]).encode('utf-8'))

    challenge = hasher.hexdigest()
    return challenge
