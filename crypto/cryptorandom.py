from Crypto import Random
from .binutils import bytes_to_int

_random_generator_file = Random.new()

def random_INTEGER(min, max):

    range = max - min
    nr_bits = max.bit_length()
    nr_bytes = int((nr_bits - 1) / 8) + 1
    random_bytes = _random_generator_file.read(nr_bytes)
    num = bytes_to_int(random_bytes)
    shift = num.bit_length() - nr_bits
    if shift > 0:
        num >>= shift
    if num >= max:
        num -= max
    return num + min
