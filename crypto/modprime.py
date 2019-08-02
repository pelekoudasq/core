"""
ElGamal cryptosystem over the group of r-residues mod p, p > 2 prime.
Defaults to r = 2, yielding the group of quadratic residues mod p
"""

import Crypto
from Crypto.Util.number import isPrime
from gmpy2 import mpz, powmod, invert, mul, add, f_mod

from .elgamal import ElGamalCrypto
from .algebra import Group, GroupElement
from .exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from .utils import int_from_bytes, hash_nums, hash_texts, random_integer



class ModPrimeElement(GroupElement):
    """
    Element of the multiplicative group Z*_p = Z_p - {0}, p > 2 prime
    """

    __slots__ = ('__value', '__modulus')

    def __init__(self, value, modulus):
        """
        :type value: mpz
        :type modulus: mpz
        """
        self.__value = value
        self.__modulus = modulus

    @property
    def value(self):
        """
        :rtype: mpz
        """
        return self.__value

    @property
    def modulus(self):
        """
        :rtype: mpz
        """
        return self.__modulus

    @property
    def bit_length(self):
        """
        :rtype: int
        """
        return self.__value.bit_length()

    def __repr__(self):
        """
        :rtype: str
        """
        return str(self.__value)

    def __hash__(self):
        """
        :rtype: int
        """
        return hash(repr(self))

    def __eq__(self, other):
        """
        :type other: ModPrimeElement or mpz
        """
        if isinstance(other, self.__class__):
            return self.__value == other.value
        else:
            return self.value == other

    def __mul__(self, other):
        """
        :type other: ModPrimeElement
        """
        result = self.__value * other.value % self.__modulus
        return self.__class__(value=result, modulus=self.__modulus)

    def __pow__(self, exp):
        """
        :type exp: mpz
        :rtype: ModPrimeElement
        """
        # # result = self.__value ** exp % self.__modulus ---> "...outrageous exponent"
        # Use gmpy2.powmod instead in order to avoid overflow in mpz type
        result = powmod(self.__value, exp, self.__modulus)
        return self.__class__(value=result, modulus=self.__modulus)

    def inv(self):
        """
        :rtype: ModPrimeElement
        """
        result = invert(self.__value, self.__modulus)
        return self.__class__(value=result, modulus=self.__modulus)

    def contained_in(self, group):
        """
        :type: ModPrimeSubgroup
        :rtype: bool
        """
        if isinstance(group, ModPrimeSubgroup) and group.modulus == self.__modulus:
            # Algebraic fact: given the q-subgroup C of Z*_p, p > 2 prime,
            # a mod p element x is contained in C iff x ^ q = 1
            return self ** group.order == 1
        return False



class ModPrimeSubgroup(Group):
    """
    Subgroup of the multiplicative group Z*_p = Z_p - {0}, p > 2 prime

    There is one such group of order q for each divisor 0 < q < p - 1 of p - 1
    and is generated by the r-power, r = (p - 1)/q, of any primitive in Z*_p

    E.g., the default value r = 2 yields the group of quadratic residues modp
    """

    __slots__ = ('__modulus', '__order', '__generator')

    def __init__(self, modulus, root_order=2):
        """
        :type modulus: mpz
        :type root_order: mpz
        """
        modulus = modulus
        root_order = root_order

        if modulus <= 2 or not isPrime(modulus):
            e = 'Provided modulus is not an odd prime'
            raise AlgebraError(e)

        if root_order <= 0 or root_order >= modulus:
            e = 'Provided order of unit-root is not in the allowed range'
            raise AlgebraError(e)

        order, s = divmod(modulus - 1, root_order)

        if s != 0:
            e = 'Provided order of unit-root does not divide the multiplicative group\'s order'
            raise AlgebraError(e)

        self.__modulus = modulus
        self.__order = order

    def __repr__(self):
        """
        :rtype: str
        """
        return '%s (%d, %d)' % (self.__class__, self.__modulus, self.__order)

    def __hash__(self):
        """
        :rtype: str
        """
        return hash(repr(self))

    @property
    def modulus(self):
        """
        :rtype: mpz
        """
        return self.__modulus

    @property
    def order(self):
        """
        :rtype: mpz
        """
        return self.__order

    def contains(self, element):
        """
        :type element: modPrimeElement
        :rtype: bool
        """
        if isinstance(element, ModPrimeElement) and element.modulus == self.__modulus:
            # Algebraic fact: given the q-subgroup C of Z*_p, p > 2 prime,
            # an mod p element x is contained in C iff x ^ q = 1
            return element ** self.__order == 1
        return False

    def set_generator(self, element):
        """
        :type element: ModPrimeElement
        """
        self.__generator = element

    @property
    def generator(self):
        """
        :rtype: ModPrimeElement
        """
        try:
            return self.__generator
        except AttributeError:
            e = 'No generator has yet been specified for this group'
            raise AlgebraError(e)

    def generate(self, exponent):
        """
        :type exponent: mpz
        :rtype: ModPrimeElement
        """
        return self.__generator ** exponent

    def random_exponent(self):
        """
        Returns a random exponent > 1, bounded by the group's order

        :rtype: mpz
        """
        exponent = random_integer(2, self.__order)
        return mpz(exponent)

    def random_element(self):
        """
        :rtype: ModPrimeElement
        """
        random_exp = self.random_exponent()
        return self.__generator ** random_exp

    def fiatshamir(self, *elements):
        """
        The output of this method is only involved in exponent operations

        :type: mpz or ModePrimeElement
        :rtype: mpz
        """

        p = self.__modulus
        q = self.__order
        g = self.__generator.value

        # Convert to mpz if ModPrimeElement
        elements = [x.value if isinstance(x, ModPrimeElement) else x for x in elements]

        digest = hash_nums(p, q, g, *elements)
        reduced = int_from_bytes(digest)
        output = self.generate(reduced).value

        return output       # g ^ ( H( p | g | q | elements)  modq )  modp

    def add_exponents(self, *args):
        """
        :type *args: mpz
        :rtype: mpz
        """
        return sum(args) % self.__order


    def algebraize(self, *texts):
        """
        :type *texts: str
        :rtype: ModPrimeElement
        """

        p = self.__modulus
        q = self.__order
        g = self.__generator.value

        hashed_params = hash_nums(p, q, g).hex()
        hashed_texts = hash_texts(hashed_params, *texts)

        exp = f_mod(int_from_bytes(hashed_texts), q)

        return self.generate(exp)



class ModPrimeCrypto(ElGamalCrypto):

    MIN_MOD_SIZE = 2048
    MIN_GEN_SIZE = 2000

    GroupElement = ModPrimeElement
    Group = ModPrimeSubgroup

    __slots__ = ('__group')


    def __init__(self, modulus, primitive, root_order=2,
                 check_3mod4=True, prime_order=True, min_mod_size=None, min_gen_size=None):
        """
        Assumes that the provided `primitive` g0 is indeed a primitive mod p (i.e., generates
        the multiplicative group Z*_p) or, equivalently, it is a primitive (p - 1)-root of 1
        (i.e., g0 ^ (p - 1) = 1 and g0 ^ k != 1 for all 0 < k < p - 1)

        :type modulus: int
        :type primitive: int
        :type root_order: int
        :type check_3mod4: bool
        :type prime_order: bool
        :type min_mod_size: int
        :type min_gen_size: int
        """

        # Type conversion

        modulus = mpz(modulus)                                   # p
        primitive = ModPrimeElement(mpz(primitive), modulus)     # g0
        root_order = mpz(root_order)                             # r

        # Resolve group

        try:
            group = ModPrimeSubgroup(modulus, root_order)
        except AlgebraError:
            raise

        self.__group = group

        # Resolve generator

        # Algebraic fact: given a primitive g0 of Z*_p, p > 2 smooth, and 1 < r < p - 1
        # with r | p - 1, then g0 ^ r generates the q-subgroup of Z*_p, q = (p - 1)/r
        generator = primitive ** root_order

        try:
            self.__group.set_generator(generator)
        except AlgebraError:
            raise

        # System validation

        if check_3mod4 and modulus % 4 != 3:
            e = 'Provided modulus is not 3 mod 4'
            raise WrongCryptoError(e)

        if prime_order and not isPrime(group.order):
            e = 'Order of the requested group is not prime'
            raise WrongCryptoError(e)

        MIN_MOD_SIZE = min_mod_size or self.__class__.MIN_MOD_SIZE
        MIN_GEN_SIZE = min_gen_size or self.__class__.MIN_GEN_SIZE

        if modulus.bit_length() < MIN_MOD_SIZE:
            e = 'Provided modulus is < %d bits long' % MIN_MOD_SIZE
            raise WeakCryptoError(e)

        if self.__group.generator.bit_length < MIN_GEN_SIZE:
            e = 'Generator is < %d bits long' % MIN_GEN_SIZE
            raise WeakCryptoError(e)

        # ------------------------------------

        # super().__init__(self.__class__, config, *opts)



# --------------------------------- Externals ---------------------------------

    @property
    def system(self):
        """
        :rtype: dict
        """
        __group = self.__group

        p = int(__group.modulus)
        q = int(__group.order)
        g = int(__group.generator.value)

        return {'modulus': p, 'order': q, 'generator': g}


    @property
    def group(self):
        """
        :rtype: ModPrimeSubgroup
        """
        return self.__group


    @property
    def groupElementType(self):
        """
        """
        pass


    def keygen(self, private_key=None, schnorr=True):
        """
        Generates a keypair of the form

        {
            'private': mpz,
            'public': {
                'value': ModPrimeElement,
                'proof': {
                    'commitment': ModPrimeElement
                    'challenge': mpz
                    'response': mpz
                }
            }
        }

        :type private_key: mpz
        :type schnorr: bool
        :rtype: dict
        """

        __group = self.__group

        key = dict()

        if private_key is None:
            private_key = __group.random_exponent()             # 1 < x < q

        elif not 1 < private_key < __group.order:
            e = 'Provided private key exceeds the allowed range'
            raise InvalidKeyError(e)

        key.update({'private': private_key})

        public_key = __group.generate(private_key)              # y = g ^ x modp
        public = dict({'value': public_key})

        if schnorr is True:
            proof = self.schnorr_proof(private_key, public_key)
            public.update({'proof': proof})

        key.update({'public': public})
        return key


    def get_as_element(self, public_key):
        """
        Assumes a dictionary of the form

        {
            'value: ModPrimeElement,
            'proof: ...
        }

        :type public_key: dict
        :rtype: ModPrimeElement
        """
        return public_key['value']

    def get_as_integer(self, public_key):
        """
        Returns the numerical value of the provided public key, assuming a
        dictionary of the form

        {
            'value: ModPrimeElement,
            'proof: ...
        }

        :type public_key: dict
        :rtype: int
        """
        return int(public_key['value'].value)


    def validate_key(self, public_key):
        """
        Accepts a dictionary of the form

        {
            'value': ModPrimeElement,
            'proof': {
                'commitment': ModPrimeElement,
                'challenge': mpz,
                'response': mpz
            }
        }

        :type public_key: dict
        :rtype: bool
        """

        try:
            proof = public_key['proof']
        except KeyError:
            # No proof has been provided together with the public key
            return False

        public_key = public_key['value']

        if not public_key.contained_in(self.__group):
            return False

        return self.schnorr_verify(proof=proof, public=public_key)


    def sign_text_message(self, message, private_key):
        """
        Returned signed message is of the form

        {
            'message': str,
            'signature': {
                'e': ModPrimeElement
                'r': ModPrimeElement
                's': mpz
            }
        }

        :type message: str
        :type private_key: mpz
        :rtype: dict
        """

        element = self.__group.algebraize(message)
        signature = self.sign_element(element, private_key)
        signed_message = {
            'message': message, 'signature': signature
        }

        return signed_message


    def verify_text_signature(self, signed_message, public_key):
        """
        Provided signed message is of the form

        :type signed_message: {
            'message': str,
            'signature': {
                'e': ModPrimeElement
                'r': ModPrimeElement
                's': mpz
            }
        }

        and provided public key is assumed to come along with proof-of knowledge
        in the form

        {
            'value': ModPrimeElement,
            'proof': ...
        }

        :type signed_message: dict
        :type public_key: dict
        :rtype: bool
        """

        message = signed_message['message']
        signature = signed_message['signature']

        element = self.__group.algebraize(message)

        if element != signature['e']:
            return False

        return self.verify_element_signature(signature, public_key['value'])


# --------------------------------- Internals ---------------------------------

    def schnorr_proof(self, secret, public, *extras):
        """
        Implementation of Schnorr protocol from the prover's side (non-interactive)

        Returns proof-of-knowldge of the discrete logarithm x (`secret`) of y (`public`).
        `*extras` are to be used in the Fiat-Shamir heuristic. The proof has the form

        {
            'commitment': ModPrimeElement
            'challenge': mpz
            'response': mpz
        }

        :type secret: mpz
        :type public: modPrimeElement
        :type *extras: mpz or int or ModPrimeElement
        :rtype: dict
        """

        __group = self.__group

        randomness = __group.random_exponent()          # r
        commitment = __group.generate(randomness)       # g ^ r

        challenge  = __group.fiatshamir(
            public,
            commitment,
            *extras)     # c = g ^ ( H( p | g | q | y | g ^ r | extras ) modq ) modp

        response = __group.add_exponents(randomness, challenge * secret) # r + c * x

        return {
            'commitment': commitment,
            'challenge': challenge,
            'response': response
        }


    def schnorr_verify(self, proof, public, *extras):
        """
        Implementation of Schnorr protocol from the verifier's side (non-interactive)

        Validates the demonstrated proof-of-knowledge (`proof`) of the discrete logarithm of
        y (`public`). `*extras` are assumed to have been used in the Fiat-Shamir heuristic

        Provided proof has the form

        {
            'commitment': ModPrimeElement
            'challenge': mpz
            'response': mpz
        }

        :type proof: dict
        :type public: modPrimeElement
        :type *extras: mpz or int or ModPrimeElement
        """
        __group = self.__group

        commitment = proof['commitment']    # g ^ r
        challenge = proof['challenge']      # c
        response = proof['response']        # s

        # Check correctness of chalenge:
        # c == g ^ ( H( p | g | q | y | g ^ r | extras ) modq ) modp ?
        _challenge = __group.fiatshamir(
            public,
            commitment,
            *extras)

        if _challenge != challenge:
            return False

        # g ^ s modp == (g ^ r) * (y ^ c) modp ?
        return __group.generate(response) == commitment * (public ** challenge)


    def chaum_pedersen_proof(self, ddh, z):
        """
        Implementation of Chaum-Pedersen protocol from the prover's side (non-interactive)

        Returns zero-knowledge proof that the provided 3-ple `ddh` is a DDH with respect
        to the generator g of the cryptosystem's underlying group, i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q

        The provided `ddh` is of the form

                    [ModPrimeElement, ModPrimeElement, ModPrimeElement]

        and the returned proof of the form

        {
            'base_commitment': ModPrimeElement
            'message_commitment': ModPrimeElement
            'challenge': mpz
            'response': mpz
        }

        :type ddh: list
        :type z: mpz
        :rtype: dict
        """

        __group = self.__group

        u, v, w = ddh

        randomness = __group.random_exponent()          # 1 < r < q

        g_commitment = __group.generate(randomness)     # g ^ r
        u_commitment = u ** randomness                  # u ^ r

        challenge = __group.fiatshamir(
            u, v, w,
            g_commitment,
            u_commitment)   # c = g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp

        response = __group.add_exponents(randomness, challenge * z)

        return {
            'base_commitment': g_commitment,        # g ^ r
            'message_commitment': u_commitment,     # u ^ r
            'challenge': challenge,                 # c
            'response': response                    # s = r + c * z  modq
        }


    def chaum_pedersen_verify(self, ddh, proof):
        """
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Validates the demonstrated zero-knowledge `proof` that the provided 3-ple `ddh` is a
        DDH with respect to the generator g of the cryptosystem's underlying group, i.e., of
        the form
                                (u, v, g ^ (x * z) modp)

        where u = g ^ x modp, v = g ^ z modp with 0 <= x, z < q

        The provided `ddh` is of the form

                    [ModPrimeElement, ModPrimeElement, ModPrimeElement]

        and the provided `proof` of the form

        {
            'base_commitment': ModPrimeElement
            'message_commitment': ModPrimeElement
            'challenge': mpz
            'response': mpz
        }

        :type ddh: list
        :type proof: dict
        :rtype: bool
        """

        __group = self.__group

        u, v, w = ddh

        g_commitment = proof['base_commitment']         # g ^ r
        u_commitment = proof['message_commitment']      # u ^ r
        challenge = proof['challenge']                  # c
        response = proof['response']                    # s

        # Check correctness of challenge:
        # c == g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp ?
        _challenge = __group.fiatshamir(
            u, v, w,
            g_commitment,
            u_commitment)

        if _challenge != challenge:
            return False

        # Verify prover's commitment to presumed randomness:
        # g ^ s == g ^ r * v ^ c  modp ?
        if __group.generate(response) != g_commitment * (v ** challenge):
            return False

        # Verify that the provided u is of the form g ^ (k * z) for some k (and
        # thus k = x due to prover's commitment to randomness r):
        # u ^ s == u ^ r * w ^ c  modp ?
        return u ** response == u_commitment * (w ** challenge)


    def sign_element(self, element, private_key):
        """
        Returned signed element is of the form

        {
            'e': ModPrimeElement,
            'r': ModPrimeElement,
            's': mpz
        }

        :type element: ModPrimeElement
        :type private_key: mpz
        :rtype: dict
        """

        __group = self.__group
        __p = __group.modulus

        elem_value = element.value

        while 1:
            u = __p - 1
            w = 2 * random_integer(3, __p) - 1
            v = invert(w, u)
            r = __group.generate(w)
            s = f_mod(mul(v, f_mod(add(elem_value, - mul(r.value, private_key)), u)), u)
            if s!= 0:
                break

        return {'e': element, 'r': r, 's': s}


    def verify_element_signature(self, signature, public_key):
        """
        Privided signature is of the form

        {
            'e': ModPrimeElement
            'r': ModPrimeElement
            's': mpz
        }

        :type signature: dict
        :type public_key: ModPrimeElement
        :rtype: bool
        """

        __group = self.__group

        e = signature['e']
        r = signature['r']
        s = signature['s']

        if not 0 < r.value < __group.modulus:
            return False

        # g ^ e == y ^ r * r ^ s modp ?

        return __group.generate(e.value) == (public_key ** r.value) * (r ** s)


    def encrypt_element(self, element, public_key, randomness=None):
        """
        :type element: ModPrimeElement
        :type public_key: ModPrimeElement
        :type randomness: mpz
        """

        __group = self.__group

        p = __group.modulus
        q = __group.order

        __element = element.value

        __element += 1
        if __element >= q:
            e = 'Element to encrypt exceeds possibilities'
            raise EncryptionNotPossible(e)

        if randomness is None:
            randomness = random_integer(1, q)
        elif not 0 < randomness < q:
            e = 'Provided randomness exceeds order of group'
            raise EncryptionNotPossible(e)

        if powmod(__element, q, p) != 1:
            __element = mod(- __element, p)

        element = ModPrimeElement(value=__element, modulus=p)

        decryptor = __group.generate(randomness)
        ciphertxt = element * (public_key ** randomness)

        # g ^ r modp, m * y ^ r modp
        return decryptor, ciphertxt




# ------------------------------- Construction -------------------------------


    @staticmethod
    def generate_system(config):
        """
        """
        pass


    @classmethod
    def validate_system(cls, system, check_3mod4=True):
        """
        """
        pass
