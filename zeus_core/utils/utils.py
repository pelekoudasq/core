# The integer representing in LSB the provided string's UTF-8 encoding
int_from_bytes = lambda _bytes: int.from_bytes(_bytes, byteorder='little')

def bit_iterator(nr, infinite=True):
    """
    Generates the sequence of bits comprising the provided integer's binary
    representation, beginning from the least significant digit

    If `infinite` is set equal to `False`, the generator will get exhausted
    (`StopIterationError`) after the actual bits are exhausted; otherwise
    zeroes will get generated to infinity

    :type nr:
    :type infinite: bool
    """
    while nr:
        yield nr & 1
        nr >>= 1

    if not infinite:
        return

    while 1:
        yield 0


#TODO
def directory_to_binary(directory):
    pass

def binary_to_directory(output_dir, data):
    pass
