from hashlib import sha256
import Crypto.Util.number as number

from .exceptions import (UnknownCryptoError, WrongConfigKeysError,
                        WrongCryptoError, WeakCryptoError,
                        AlgebraicIncompatibilityError,
                        ImpossibleEncryptionError)
from .cryptorandom import random_integer

MIN_MOD_BIT_SIZE = 2048
MIN_GEN_BIT_SIZE = 2000

INTEGER  = 'integer'
ELLIPTIC = 'elliptic'

CRYPTO_TYPES = [INTEGER, ELLIPTIC]

CONFIG_KEYS = {
    INTEGER: {'modulus', 'root_order', 'element'},
    ELLIPTIC: set()
}

PARAMETER_KEYS = {
    INTEGER: {'modulus', 'order', 'generator'},
    ELLIPTIC: set()
}

OPERATIONS = {
    INTEGER: {'mult', 'inv', 'pow'},
    ELLIPTIC: set()
}

# Optimize common  operations over the whole ring of integers

try:
    from gmpy2 import mul, f_divmod, f_mod, powmod, invert

except ImportError:

    print('WARNING: Could not import from gmpy2. Falling back to SLOW crypto.')

    _mul = lambda x, y: x * y
    _divmod = divmod
    _mod = lambda x, y: x % y
    _pow = pow
    _inv = lambda x, p: pow(x, p - 2, p)            # inverse mod an odd prime p

else:
    _mul = lambda x, y: int(mul(x, y))

    def _divmod(x, y):
        q, r = f_divmod(x, y)
        return int(q), int(r)

    _mod = lambda x, y: int(f_mod(x, y))
    _pow = lambda x, y, z: int(powmod(x, y, z))
    _inv = lambda x, p: int(invert(x, p))           # inverse mod an odd prime p


# ----------------------------------- Makers -----------------------------------


def make_cryptosys(config, _type):
    """
    Constructs and returns a cryptosystem in the dictionary form

        {
            "parameters": {
                ...
            },
            "type":
        }

    where the "type" value is the provided `_type` (either INTEGER or ELLIPTIC)
    and the "parameters" value is a dictionary constructed in accordance with
    the provided `config`. Appropriate exceptions get raised if the provided
    configurations and type are not compatible
    """

    cryptosys = dict()

    if _type not in CRYPTO_TYPES:
        e = 'Type %s of requested cryptosystem is not supported' % _type
        raise UnknownCryptoError(e)

    cryptosys.update({'type': _type})

    config_keys = set(config.keys())
    if config_keys != CONFIG_KEYS[_type]:
        e = 'Provided config keys {} do not exactly correspond to the required ones'.format(config_keys)
        raise WrongConfigKeysError(e)

    if _type is INTEGER:

        modulus = config['modulus']         # p
        root_order = config['root_order']   # r
        element = config['element']         # g0

        if modulus <= 2 or not number.isPrime(modulus):
            e = 'Provided modulus is not an odd prime'
            raise WrongCryptoError(e)

        nr_elements = modulus - 1   # p - 1

        if element < 2 or element > nr_elements - 1:
            e = 'Provided element does not belong to the multiplicative group'

        order, remainder = _divmod(nr_elements, root_order)   # q = (p - 1)/r

        if remainder != 0:
            e = 'Provided order does not divide the multiplicative group\'s order'
            raise WrongCryptoError(e)

        if not number.isPrime(order):
            e = 'Order of the requested group is not prime'
            raise WrongCryptoError(e)

        generator = _pow(element, root_order, modulus)    # g = g0 ^ r

        if generator == 1:
            # Algebraic fact: given an element 1 < x < p for prime p
            # and 1 < r < p - 1 with r | p - 1, then x ^ (p - 1)/r
            # generates the n-subgroup of Z^*_p if it is not 1
            e = 'Provided element cannot yield the generator of the requested subgroup'
            raise WrongCryptoError(e)

        cryptosys.update({
            'parameters': {
                'modulus': modulus,
                'order': order,
                'generator': generator
            }
        })

    elif _type is ELLIPTIC:
        pass

    return cryptosys


def make_operations(cryptosys):
    """
    Returns the algebraic operations specific to the provided cryptosystem,
    assuming it is algebraically valid
    """

    _type = cryptosys['type']

    if _type is INTEGER:

        p = cryptosys['parameters']['modulus']

        mult = lambda a, b: _mod(_mul(a, b), p)     # Z_p mulitplication a * b = a * b modp
        inv  = lambda a: _inv(a, p)                 # inversion a ^ -1 in Z*_p
        pow  = lambda a, b: _pow(a, b, p)           # Z_p raising to power a ^ b = a ** b  modp

        return {
            'mult': mult,
            'inv': inv,
            'pow': pow
        }

    elif _type is ELLIPTIC:
        pass

def make_hash_func(cryptosys):
    """
    Returns an algebraically flavored hash function specific to the provided
    cryptosystem, assuming its agebraic validity
    """

    _type = cryptosys['type']

    if _type is INTEGER:

        p, g, q = extract_parameters(cryptosys)

        # g ^ H( p | g | q | elements)
        def hash_func(*elements):
            digest = hash_numbers(p, g, q, *elements)
            readuced = _mod(bytes_to_int(digest), q)
            return _pow(g, reduced, p)

    elif _type is ELLIPTIC:
        pass

    return hash_func


def make_generate_keypair(cryptosys):
    """
    Returns the algebraic keygen functionality specific to the provided
    cryptosystem, assuming its algebraic validity
    """

    _type = cryptosys['type']

    if _type is INTEGER:

        p, g = extract_parameters(cryptosys)[:2]

        # FIX: redesign it in the Schnorr context
        def generate_keypair(private_key):
            public_key = _pow(g, private_key, p)
            return (private_key, public_key)

    elif _type is ELLIPTIC:
        pass

    return generate_keypair

def make_encrypt(cryptosys):
    """
    Returns the algebraic encryption function specific to the provided
    cryptosystem, assuming its algebraic validity
    """

    _type = cryptosys['type']

    if _type is INTEGER:

        p, g, q = extract_parameters(cryptosys)

        def encrypt(element, public_key, randomness=None):

            element += 1
            if element >= q:
                e = 'Element to encrypt exceeds possibilities'
                raise ImpossibleEncryptionError(e)

            if randomness is None:
                randomness = random_integer(1, q)
            elif not 1 <= randomness <= q - 1:
                e = 'Provided randomness exceeds order of group'
                raise ImpossibleEncryptionError(e)

            if _pow(element, q, p) != 1:
                element = mod(-element, p)

            decryptor = _pow(g, randomness, p)
            cipher    = _mod(_mul(element, _pow(public_key, randomness, p)), p)

            return decryptor, cipher

    elif _type is ELLIPTIC:
        pass

    return encrypt

# ---------------------------------- Helpers ----------------------------------


def extract_parameters(cryptosys):
    """
    Extracts in a tuple the parameters of the provided cryptosystem
    """

    parameters = cryptosys['parameters']
    _type = cryptosys['type']

    if _type is INTEGER:
        return parameters['modulus'], parameters['generator'], parameters['order']

    elif _type is ELLIPTIC:
        pass


def hash_numbers(*args):
    """
    Returns (bytes) the SHA256-digest of the concatenation
    of the provided numbers' hexadecimal representations
    """
    hasher = sha256()
    update = hasher.update
    for number in args:
        # update(("%x:" % number).encode())
        update(bytes("%x" % number, 'utf-8'))
    return hasher.digest()

def validate_cryptosys(cryptosys, min_mod_bit_size=MIN_MOD_BIT_SIZE,
                       min_gen_bit_size=MIN_GEN_BIT_SIZE, check_3mod4=False):
    """
    Validates algebraic correctness and cryptographical strength of the provided
    cryptosystem. Returns `True` in case of validation, otherwise an appropriate
    exception gets raised
    """

    e = None

    _type = cryptosys['type']

    if _type is INTEGER:

        p, g, q = extract_parameters(cryptosys)

        if p <= 2 or not number.isPrime(p):
            e = 'Modulus is not an odd prime'
            raise WrongCryptoError(e)

        if check_3mod4 and _mod(p, 4) != 3:
            e = 'Modulus is not 3 mod 4'
            raise WrongCryptoError(e)

        if not number.isPrime(q):
            e = 'Order of ciphers\'s group is not prime'
            raise WrongCryptoError(e)

        if _mod(p - 1, q) != 0:
            e = 'Order does not divide the multiplicative group\'s order'
            raise WrongCryptoError(e)

        if not 1 < g < p or _pow(g, q, p) != 1:
            e = 'Generator is not valid'
            raise WrongCryptoError(e)

        if p.bit_length() < min_mod_bit_size:
            e = 'Modulus is < %d bits long' % min_mod_bit_size
            raise WeakCryptoError(e)

        if g.bit_length() < min_gen_bit_size:
            e = 'Generator is < %d bits long' % min_gen_bit_size
            raise WeakCryptoError(e)

    elif _type is ELLIPTIC:
        pass

    return not e

# ------------------------------------------------------------------------------

# def make_ElGamal_crypto(modulus, element):
#
#     try:
#         cryptosys = make_cryptosys({
#             'modulus': modulus,
#             'root_order': 2,
#             'element': element
#         }, _type=INTEGER)
#
#     except WrongCryptoError:
#         raise
#
#     # return cryptosys
#
# def generate_keypair(cryptosys, private_key=None):
#
#     _type = cryptosys['type']
#
#     if _type is INTEGER:
#
#         modulus = parameters['modulus']
#         generator = cryptosys['generator']
#         public_key = _pow(generator, private_key, modulus)
#
#     elif _type is ELLIPTIC:
#         pass
#
#     else:
#         e = 'Type of cryptosystem could not be recognized'
#         raise UnknownCryptoError(e)
#
#     cryptosys.update({
#         'private_key': private_key,
#         'public_key': public_key
#     })
#
# def export_primitives():
#     pass
