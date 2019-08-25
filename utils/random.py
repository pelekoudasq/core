from Crypto import Random
from gmpy2 import mpz

from .utils import int_from_bytes

_random_generator_file = Random.new()

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
