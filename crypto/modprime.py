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
    # def __init__(self, config, check_3mod4=True):

        config = {
            'modulus': modulus,
            'element': element,
            'root_order': root_order
        }

        opts = [check_3mod4]

        # try:
        #     modulus = config['modulus']
        #     element = config['element']
        #     root_order = config['root_order']
        # except KeyError:
        #     raise

        super().__init__(self.__class__, config, *opts)

        # modulus = config['modulus']
        # element = config['order']
        # root_order = config['root_order']

        # super().__init__(modulus, element, root_order, check_3mod4)

        # try:
        #     system = ModPrimeCrypto.generate_system(modulus, element, root_order)
        # except WrongCryptoError:
        #     raise
        #
        # self.__system = system
        #
        # try:
        #     ModPrimeCrypto.validate_system(system, check_3mod4=check_3mod4)
        # except (WrongCryptoError, WeakCryptoError):
        #     raise

        # self.__p = self.__system['modulus']
        # self.__q = self.__system['order']
        # self.__g = self.__system['generator']

    def set_params(self, system):
        self.__p = system['modulus']
        self.__q = system['order']
        self.__g = system['generator']


    @property
    def system(self):
        return {'modulus': self.__p, 'order': self.__q, 'generator': self.__g}

    # Algebraic operations

    def mul(self, x, z):
        """
        Group multiplication: (x, z) ---> x * z modp
        """
        return mod(mul(x, z), self.__p)

    def inv(self, x):
        """
        Returns inverse group element: x ---> x ^ -1 modp
        """
        return inv(x, self.__p)

    def pow(self, x, z):
        """
        Group powering: (x, z) ---> x ^ z modp
        """
        return pow(x, z, self.__p)

    def gen(self, z):
        """
        Group-element generation: z ---> g ^ z mod p
        """
        return pow(self.__g, z, self.__p)

    def add(self, a, b):
        """
        Exponent addition: (a, b) ---> (a + b) modp
        """
        return mod(add(a, b), self.__q)


# --------------------------------- Interface ---------------------------------

    def schnorr_proof(self, secret, public, *extras):
        """
        Implementation of Schnorr protocol from the prover's side (non-interactive)

        Returns proof-of-knowldge of the discrete logarithm x (`secret`) of y (`public`).
        `*extras` are to be used in the Fiat-Shamir heuristic.
        """

        p, q, g = self.params

        randomness = random_integer(2, q)       # r
        commitment = self.gen(randomness)# pow(g, randomness, p)     # g ^ r

        challenge  = self.fiatshamir(
            p, g, q,
            public,
            commitment,
            *extras)              # c = g ^ ( H( p | g | q | y | g ^ r | extras ) modq ) modp

        response = self.add(randomness, mul(challenge, secret))# mod(add(randomness, mul(challenge, secret)), q)   # s = r + c * x  modq

        return {'commitment': commitment, 'challenge': challenge, 'response': response}

         # commitment, challenge, response  # g ^ r, c, s


    def schnorr_verify(self, proof, public, *extras):
        """
        Implementation of Schnorr protocol from the verifier's side (non-interactive)

        Validates the demonstrated proof-of-knowledge (`proof`) of the discrete logarithm of
        y (`public`). `*extras` are assumed to have been used in the Fiat-Shamir heuristic
        """

        p, q, g = self.params

        commitment = proof['commitment']    # g ^ r
        challenge = proof['challenge']      # c
        response = proof['response']        # s

        # commitment, challenge, response = proof     # g ^ r, c, s

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

        return self.gen(response) == self.mul(commitment, self.pow(public, challenge))
        # return pow(g, response, p) == mod(mul(commitment, pow(public, challenge, p)), p)


    def chaum_pedersen_proof(self, ddh, z):
        """
        Implementation of Chaum-Pedersen protocol from the prover's side (non-interactive)

        Returns zero-knowledge proof that the provided 3-ple `ddh` is a DDH with respect
        to the generator g of the cryptosystem's underlying group, i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q
        """

        p, q, g = self.params

        u, v, w = ddh

        randomness = random_integer(2, q)          # 1 < r < q

        g_commitment = self.gen(randomness)     # g ^ r
        u_commitment = self.pow(u, randomness)     # u ^ r

        challenge = self.fiatshamir(
            p, g, q,
            u, v, w,
            g_commitment,
            u_commitment)   # c = g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp

        response = self.add(randomness, mod(mul(challenge, z), self.__q))
        # response = self.add(randomness, self.mul(challenge, z))         # s = r + c * z  modq

        return {
            'base_commitment': g_commitment,        # g ^ r
            'message_commitment': u_commitment,     # u ^ r
            'challenge': challenge,                 # c
            'response': response                    # s
        }


    def chaum_pedersen_verify(self, ddh, proof):
        """
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Validates the demonstrated zero-knowledge `proof` that the provided 3-ple `ddh` is a
        DDH with respect to the generator g of the cryptosystem's underlying group, i.e., of
        the form
                                (u, v, g ^ (x * z) modp)

        where u = g ^ x modp, v = g ^ z modp with 0 <= x, z < q
        """

        p, q, g = self.params

        u, v, w = ddh

        g_commitment = proof['base_commitment']         # g ^ r
        u_commitment = proof['message_commitment']      # u ^ r
        challenge = proof['challenge']                  # c
        response = proof['response']                    # s

        # g_commitment, u_commitment, challenge, response = proof     # g ^ r, u ^ r, c, s

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

        if self.gen(response) != self.mul(g_commitment, self.pow(v, challenge)):
            return False

        # Verify that the provided u is of the form g ^ (k * z) for some k, and
        # thus k = x due to verified prover's commitment to randomness r:
        # u ^ s == u ^ r * w ^ c  modp ?

        return self.pow(u, response) == self.mul(u_commitment, self.pow(w, challenge))


    def keygen(self, private_key=None, schnorr=False):
        """
        """

        p, q, g = self.params

        if private_key is None:

            private_key = self.random_element()                 # 1 < x < q

        elif not 1 < private_key < q:
            e = 'Provided private key exceeds the allowed range'
            raise InvalidKeyError(e)

        public_key = self.gen(private_key)                    # y = g ^ x modp

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
            r = self.gen(w)# pow(g, w, p)
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

        x0 = self.mul(self.pow(public_key, r), self.pow(r, s))
        x1 = self.gen(e)

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
        elif not 0 < randomness < q:
            e = 'Provided randomness exceeds order of group'
            raise EncryptionNotPossible(e)

        if self.pow(element, q) != 1:
            element = mod(- element, p)

        decryptor = self.pow(g, randomness)
        cipher    = self.mul(element, self.pow(public_key, randomness))

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
        r = random_integer(2, self.__q)
        return self.gen(r)


    def algebraize(self, *texts):
        """
        """

        p, q, g = self.params

        hashed_params = hash_nums(p, q, g).hex()
        hashed_texts = hash_texts(hashed_params, *texts)

        exp = mod(bytes_to_int(hashed_texts), q)

        return self.gen(exp)


    def fiatshamir(self, *elements):
        """
        """

        p, q, g = self.params

        digest = hash_nums(p, g, q, *elements)
        reduced = mod(bytes_to_int(digest), q)
        output = self.gen(reduced)

        return output   # g ^ ( H( p | g | q | elements)  modq )  modp


# ------------------------------- Static methods -------------------------------

    @staticmethod
    # def generate_system(modulus, element, root_order):
    def generate_system(config):
        """
        """

        modulus = config['modulus']
        element = config['element']
        root_order = config['root_order']

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
