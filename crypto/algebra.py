import Crypto

# Optimize common integer operations

try:
    from gmpy2 import _add, mul, f_divmod, f_mod, powmod, invert

except ImportError:

    print('WARNING: Could not import from gmpy2. Falling back to SLOW crypto.')

    _add = lambda x, y: x + y
    _mul = lambda x, y: x * y
    _divmod = divmod
    _mod = lambda x, y: x % y
    _pow = pow
    _inv = Crypto.Util.number.inverse               # x ^ -1 mod p

else:

    _add = lambda x, y: int(_add(x, y))              # x + y
    _mul = lambda x, y: int(mul(x, y))              # xy

    def _divmod(x, y):
        q, r = f_divmod(x, y)
        return int(q), int(r)                       # x/y, x mod y

    _mod = lambda x, y: int(f_mod(x, y))            # x mod y
    _pow = lambda x, y, z: int(powmod(x, y, z))     # x ^ y mod z
    _inv = lambda x, p: int(invert(x, p))           # x ^ -1 mod p


# Checks if x is a ((p - 1)/q)-residue p, assuming that g is a generator of
# these residues. Reduces to Legendre symbol if q = (p - 1)/2
isresidue = lambda x, q, p: _pow(x, q, p) == 1
