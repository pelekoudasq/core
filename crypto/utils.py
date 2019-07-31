from hashlib import sha256
from Crypto import Random

_random_generator_file = Random.new()

# Returns the integer represented in LSB by the provided string's UTF-8 encoding
int_from_bytes = lambda _bytes: int.from_bytes(_bytes, byteorder='little')

# Returns the SHA256-digest of the concatenation of the provided numbers' hexadecimal representations
hash_nums = lambda *nums: sha256((''.join('%x:' % _ for _ in nums)).encode()).digest()

# Returns the SHA256-digest of the concatenation of the provided strings
hash_texts = lambda *args: sha256(('\x00'.join(args)).encode()).digest()

def random_integer(min, max):
    """
    min: inclusive lower bound
    max: exclusive upper bound
    """

    range = max - min
    nr_bits = max.bit_length()
    nr_bytes = int((nr_bits - 1) / 8) + 1
    random_bytes = _random_generator_file.read(nr_bytes)
    num = int_from_bytes(random_bytes)
    shift = num.bit_length() - nr_bits
    if shift > 0:
        num >>= shift
    if num >= max:
        num -= max
    return num + min

# def hash_nums(*args):
#     """
#     Returns (bytes) the SHA256-digest of the concatenation
#     of the provided numbers' hexadecimal representations
#     """
#
#     hasher = sha256()
#     update = hasher.update
#
#     for arg in args:
#         update(("%x:" % arg).encode())
#
#     return hasher.digest()  # H( arg1 | ... | arg2)
#
#
# def hash_texts2(*args):
#     """
#     """
#     hasher = sha256()
#     hasher.update(('\x00'.join(args)).encode())
#
#     return hasher.digest()  # H( arg1 | ... | arg2)
