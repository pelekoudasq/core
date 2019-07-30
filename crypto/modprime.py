import Crypto
from Crypto.Util.number import isPrime

from .elgamal import ElGamalCrypto
from .exceptions import WrongCryptoError, WeakCryptoError
from .algebra import add, mul, divmod, mod, pow, inv
from .utils import bytes_to_int, hash_nums, hash_texts, random_integer


class ModPrimeCrypto(ElGamalCrypto):

    MIN_MOD_SIZE = 2048
    MIN_GEN_SIZE = 2000

    __slots__ = ('__p', '__q', '__g')


    def __init__(self, modulus, element, root_order=2, check_3mod4=True):

        try:
            system = ModPrimeCrypto.generate_system(modulus, element, root_order)
        except WrongCryptoError:
            raise

        try:
            ModPrimeCrypto.validate_system(system, check_3mod4=check_3mod4)
        except (WrongCryptoError, WeakCryptoError):
            raise

        self.__p = system['modulus']
        self.__q = system['order']
        self.__g = system['generator']


    @property
    def system(self):
        return {'modulus': self.__p, 'order': self.__q, 'generator': self.__g}


# --------------------------------- Interface ---------------------------------

    def schnorr_proof(self, secret, public, *extras):
        """
        Implementation of Schnorr protocol from the prover's side (non-interactive)

        Returns proof-of-knowldge of the discrete logarithm x (`secret`) of y (`public`).
        `*extras` are to be used in the Fiat-Shamir heuristic.
        """

        p, q, g = self.params

        randomness = random_integer(2, q)       # r
        commitment = pow(g, randomness, p)     # g ^ r

        challenge  = self.fiatshamir(
            p, g, q,
            public,
            commitment,
            *extras)              # c = g ^ ( H( p | g | q | y | g ^ r | extras ) modq ) modp

        response = mod(add(randomness, mul(challenge, secret)), q)   # s = r + c * x  modq

        return commitment, challenge, response  # g ^ r, c, s


    def schnorr_verify(self, proof, public, *extras):
        """
        Implementation of Schnorr protocol from the verifier's side (non-interactive)

        Validates the demonstrated proof-of-knowledge (`proof`) of the discrete logarithm of
        y (`public`). `*extras` are assumed to have been used in the Fiat-Shamir heuristic
        """

        p, q, g = self.params

        commitment, challenge, response = proof     # g ^ r, c, s

        # Check correctness of chalenge:
        # c == g ^ ( H( p | g | q | y | g ^ r | extras ) modq ) modp ?

        _challenge = self.fiatshamir(
            p, g, q,
            public,
            commitment,
            *extras)

        if _challenge != challenge:
            return False

        # Proceed to proof validation: g ^ s modp == (g ^ r) * (y ^ c) modp ?

        return pow(g, response, p) == mod(mul(commitment, pow(public, challenge, p)), p)


    def chaum_pedersen_proof(self, u, v, w, z):
        """
        Implementation of Chaum-Pedersen protocol from the prover's side (non-interactive)

        Returns zero-knowledge proof that the provided 3-ple is a DDH with respect to the
        generator g of the cryptosystem's underlying group, i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q
        """

        p, q, g = self.params

        randomness = random_integer(2, q)          # 1 < r < q

        g_commitment = _prod(g, randomness, p)     # g ^ r
        u_commitment = _prod(u, randomness, p)     # u ^ r

        challenge = self.fiatshamir(
            p, g, q,
            u, v, w,
            g_commitment,
            u_commitment)   # c = g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp

        response = mod(add(randomness, mul(challenge, z)), q)         # s = r + c * z  modq

        return g_commitment, u_commitment, challenge, response           # g ^ r, u ^ r, c, s


    def chaum_pedersen_verify(self, u, v, w, proof):
        """
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Validates the demonstrated zero-knowledge `proof` that the provided 3-ple (u, v, w) is
        a DDH with respect to the generator g of the cryptosystem's underlying group, i.e.,
        of the form
                                (u, v, g ^ (x * z) modp)

        where u = g ^ x modp, v = g ^ z modp with 0 <= x, z < q
        """

        p, q, g = self.params

        g_commitment, u_commitment, challenge, response = proof     # g ^ r, u ^ r, c, s

        # Check correctness of challenge:
        # c == g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp ?

        _challenge = self.fiatshamir(
            p, g, q,
            u, v, w,
            g_commitment,
            u_commitment)

        if _challenge != challenge:
            return False

        # Verify prover's commitment to presumed randomness:
        # g ^ s == g ^ r * v ^ c  modp ?

        if pow(g, response) != mod(mul(g_commitment, pow(v, challenge, p)), p):
            return False

        # Verify that the provided u is of the form g ^ (k * z) for some k, and
        # thus k = x due to verified prover's commitment to randomness r:
        # u ^ s == u ^ r * w ^ c  modp ?

        return pow(u, response, p) == mod(mul(u_commitment, pow(w, challenge, p)), p)


    def keygen(self, private_key=None, schnorr=False):
        """
        """

        p, q, g = self.params

        if private_key is None:

            private_key = self.random_element()                 # 1 < x < q

        elif not 1 < private_key < q:
            e = 'Provided private key exceeds the allowed range'
            raise InvalidKeyError(e)

        public_key = pow(g, private_key, p)                    # y = g ^ x modp

        if schnorr is True:

            proof = self.schnorr_proof(private_key, public_key)
            return private_key, public_key, proof

        else:
            return private_key, public_key


    def sign_element(self, element, private_key):
        """
        """

        p, q, g = self.params

        while 1:
            w = 2 * random_integer(3, q) - 1
            r = pow(g, w, p)
            u = p - 1
            w = inv(w, u)
            s = mod(mul(w, mod(add(element, - mul(r, private_key)), u)), u)
            if s!= 0:
                break

        return {'e': element, 'r': r, 's': s}


    def verify_element_signature(self, signature, public_key):
        """
        """

        p, q, g = self.params

        e = signature['e']
        r = signature['r']
        s = signature['s']

        # if not 0 < r < p:
        #     return False

        x0 = mod(mul(pow(public_key, r, p), pow(r, s, p)), p)
        x1 = pow(g, e, p)

        return x0 == x1


    def sign_text_message(self, message, private_key):
        """
        """

        element = self.algebraize(message)

        signature = self.sign_element(element, private_key)

        signed_message = {'message': message, 'signature': signature}

        return signed_message


    def verify_text_signature(self, signed_message, public_key):
        """
        """

        message = signed_message['message']
        signature = signed_message['signature']

        element = self.algebraize(message)

        if element != signature['e']:
            return False

        return self.verify_element_signature(signature, public_key)


    def encrypt_element(self, element, public_key, randomness=None):
        """
        """

        p, q, g = self.params

        element += 1
        if element >= q:
            e = 'Element to encrypt exceeds possibilities'
            raise EncryptionNotPossible(e)

        if randomness is None:
            randomness = random_integer(1, q)
        elif not 1 <= randomness <= q - 1:
            e = 'Provided randomness exceeds order of group'
            raise EncryptionNotPossible(e)

        if pow(element, q, p) != 1:
            element = mod(-element, p)

        decryptor = pow(g, randomness, p)
        cipher    = mod(mul(element, pow(public_key, randomness, p)), p)

        return decryptor, cipher    # g ^ r modp, m * y ^ r modp


# --------------------------------- Internals ---------------------------------

    @property
    def params(self):
        """
        """
        modulus = self.__p
        order = self.__q
        generator = self.__g

        return modulus, order, generator


    def random_element(self):
        """
        Returns a group element g ^ r modp, where 1 < r < q random
        """
        return pow(self.__g, random_integer(2, self.__q), self.__p)


    def algebraize(self, *texts):
        """
        """

        p, q, g = self.params

        hashed_params = hash_nums(p, q, g).hex()
        hashed_texts = hash_texts(hashed_params, *texts)

        exp = mod(bytes_to_int(hashed_texts), q)

        return pow(g, exp, p)


    def fiatshamir(self, *elements):
        """
        """

        p, q, g = self.params

        digest = hash_nums(p, g, q, *elements)
        reduced = mod(bytes_to_int(digest), q)
        output = pow(g, reduced, p)

        return output   # g ^ ( H( p | g | q | elements)  modq )  modp


# ------------------------------- Static methods -------------------------------

    @staticmethod
    def generate_system(modulus, element, root_order):
        """
        """

        p, g0, r  = modulus, element, root_order

        if p <= 2 or not isPrime(p):
            e = 'Provided modulus is not an odd prime'
            raise WrongCryptoError(e)

        nr_elements = p - 1

        if g0 < 2 or g0 > nr_elements - 1:
            e = 'Provided element does not belong to the multiplicative group'

        q, s = divmod(nr_elements, r)  # q = (p - 1)/r

        if s != 0:
            e = 'Provided order does not divide the multiplicative group\'s order'
            raise WrongCryptoError(e)

        if not isPrime(q):
            e = 'Order of the requested group is not prime'
            raise WrongCryptoError(e)

        g = pow(g0, r, p)  # g = g0 ^ r  modp

        if g == 1:
            # Algebraic fact: given 1 < x < p for a smooth prime p and 1 < r < p - 1 with
            # r | p - 1, then x ^ (p - 1)/r generates the r-subgroup of Z^*_p if it is != 1
            e = 'Provided element cannot yield the requested subgroup\'s generator'
            raise WrongCryptoError(e)

        return {'modulus': p, 'order': q, 'generator': g}


    @classmethod
    def validate_system(cls, system, check_3mod4=True):
        """
        """

        p, q, g = list(system.values())

        if check_3mod4 and mod(p, 4) != 3:
            e = 'Modulus is not 3 mod 4'
            raise WrongCryptoError(e)

        if mod(p - 1, q) != 0:
            e = 'Order of subgroup does not divide the multiplicative group\'s order'
            raise WrongCryptoError(e)

        if not isPrime(q):
            e = 'Order of subgroup is not prime'
            raise WrongCryptoError(e)

        if not 1 < g < p or pow(g, q, p) != 1:
            e = 'Generator is not valid'
            raise WrongCryptoError(e)

        if p.bit_length() < cls.MIN_MOD_SIZE:
            e = 'Modulus is < %d bits long' % cls.MIN_MOD_SIZE
            raise WeakCryptoError(e)

        if g.bit_length() < cls.MIN_GEN_SIZE:
            e = 'Generator is < %d bits long' % cls.MIN_GEN_SIZE
            raise WeakCryptoError(e)

        return True
