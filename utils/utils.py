from hashlib import sha256
from Crypto import Random
from gmpy2 import mpz

_random_generator_file = Random.new()

# Returns the integer represented in LSB by the provided string's UTF-8 encoding
int_from_bytes = lambda _bytes: int.from_bytes(_bytes, byteorder='little')
# int_from_bytes = lambda _bytes: mpz(int.from_bytes(_bytes, byteorder='little'))

hash_encode = lambda string: string.encode(errors='surrogateescape')
hash_decode = lambda hashed: hashed.decode(errors='surrogateescape')

# Returns the SHA256-digest of the concatenation of the provided numbers' hexadecimal representations
# Note: Works exactly the same with mpz arguments
hash_nums = lambda *nums: sha256((''.join('%x:' % _ for _ in nums)).encode()).digest()

# Returns the SHA256-digest of the concatenation of the provided strings
hash_texts = lambda *args: sha256(('\x00'.join(args)).encode()).digest()

def extract_value(dictionary, key, cast, default=None):
	"""
	:type dictionary: dict
	:type key: str
	:type cast: function
	:type default:
	"""
	value = default
	if key in dictionary.keys():
	    if dictionary[key] is None:
	        return None
	    value = cast(dictionary[key])
	return value

def random_integer(min, max):
    """
    min (mpz or int): inclusive lower bound
    max (mpz or int): exclusive upper bound
    Returns: mpz
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
    return mpz(num) + min

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
