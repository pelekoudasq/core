
# Returns the INTEGER represented in LSB by the provided string's UTF-8 encoding

bytes_to_int = lambda _bytes: int.from_bytes(_bytes, byteorder='little')
