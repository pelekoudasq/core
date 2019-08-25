from hashlib import sha256

hash_encode = lambda string: string.encode(errors='surrogateescape')
hash_decode = lambda hashed: hashed.decode(errors='surrogateescape')

# Returns the SHA256-digest of the concatenation of
# the provided numbers' hexadecimal representations
# Note: Works exactly the same with mpz arguments
hash_nums = lambda *nums: sha256((''.join('%x:' % _ for _ in nums)).encode()).digest()

# Returns the SHA256-digest of the concatenation of the provided strings
hash_texts = lambda *args: sha256(('\x00'.join(args)).encode()).digest()

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
