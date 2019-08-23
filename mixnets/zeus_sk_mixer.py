def reencrypt(ciphertext, public_key, secret_key=None):
    """
    :type ciphertext: dict
    :type secret_key: mpz
    :rtype: dict or tuple
    """
    __group = self.__group

    if secret_key is None:
        _secret_key = self.__group.random_exponent(min=3)
    else:
        _secret_key = secret_key

    alpha, beta = self._extract_ciphertext(ciphertext)

    alpha = alpha * __group.generate(secret_key)                # a * g ^ x
    beta = beta * public_key ** secret_key                      # b * y ^ x

    ciphertext = self._set_ciphertext(alpha, beta)

    if secret_key is None:
        ciphertext, _secret_key
    return ciphertext


from itertools import chain
from hashlib import sha256
ALPHA = 0
BETA = 1

def compute_mix_challenge(cipher_mix):
    """
    :type cipher_mix: dict
    :rtype:
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

# test
# from constants import cipher_mix
# if __name__=='__main__':
#     print(compute_mix_challenge(cipher_mix))
