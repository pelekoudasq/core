import Crypto

# Optimize common integer operations

try:
    from gmpy2 import add, mul, f_divmod, f_mod, powmod, invert

except ImportError:

    print('WARNING: Could not import from gmpy2. Falling back to SLOW crypto.')

    add = lambda x, y: x + y
    mul = lambda x, y: x * y
    divmod = divmod
    mod = lambda x, y: x % y
    pow = pow
    inv = Crypto.Util.number.inverse               # x ^ -1 mod p

else:

    _add = add
    add = lambda x, y: int(_add(x, y))              # x + y
    _mul = mul
    mul = lambda x, y: int(_mul(x, y))              # xy

    def divmod(x, y):
        q, r = f_divmod(x, y)
        return int(q), int(r)                       # x/y, x mod y

    mod = lambda x, y: int(f_mod(x, y))            # x mod y
    pow = lambda x, y, z: int(powmod(x, y, z))     # x ^ y mod z
    inv = lambda x, p: int(invert(x, p))           # x ^ -1 mod p


# Checks if x is a ((p - 1)/q)-residue p, assuming that g is a generator of
# these residues. Reduces to Legendre symbol if q = (p - 1)/2
isresidue = lambda x, q, p: pow(x, q, p) == 1
