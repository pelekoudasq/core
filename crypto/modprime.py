from .elgamal import ElGamalCrypto
from .exceptions import WrongCryptoError
from .algebra import number, _add, _mul, _divmod, _mod, _pow, _inv

class ModPrimeCrypto(object):#(ElGamalCrypto):

    def __init__(self, modulus, root_order, element):

        # config = [modulus, root_order, element]
        super().__init__(modulus, root_order, element)
        # try:
        #     system = ModPrimeCrypto.generate_system(*config)
        # except WrongCryptoError:
        #     raise
        #
        # try:
        #     ModPrimeCrypto.validate_system(system)
        # except (WrongCryptoError, WeakCryptoError):
        #     raise
        #
        # self.system = system
        # ModPrimeCrypto.load_primitives(system)


    @staticmethod
    def generate_system(modulus, root_order, element):
        """
        """

        p  = modulus
        r  = root_order
        g0 = element

        if p <= 2 or not number.isPrime(p):
            e = 'Provided modulus is not an odd prime'
            raise WrongCryptoError(e)

        nr_elements = p - 1

        if g0 < 2 or g0 > nr_elements - 1:
            e = 'Provided element does not belong to the multiplicative group'

        q, s = _divmod(nr_elements, r)  # q = (p - 1)/r

        if s != 0:
            e = 'Provided order does not divide the multiplicative group\'s order'
            raise WrongCryptoError(e)

        if not number.isPrime(q):
            e = 'Order of the requested group is not prime'
            raise WrongCryptoError(e)

        g = _pow(g0, r, p)  # g = g0 ^ r

        if g == 1:
            # Algebraic fact: given 1 < x < p for a smooth prime p and 1 < r < p - 1 with
            # r | p - 1, then x ^ (p - 1)/r generates the r-subgroup of Z^*_p if it is != 1
            e = 'Provided element cannot yield the requested subgroup\'s generator'
            raise WrongCryptoError(e)

        return {
            'modulus': p,
            'generator': g,
            'order':q
        }


    @staticmethod
    def extract_parameters(system):
        """
        """

        p = system['modulus']
        q = system['order']
        g = system['generator']

        return p, g, q


    @staticmethod
    def validate_system(system):
        """
        """

        p, q, g = ModPrimeCrypto.extract_parameters(system)

        if _mod(p, 4) != 3:
            e = 'Modulus is not 3 mod 4'
            raise WrongCryptoError(e)

        if not number.isPrime(q):
            e = 'Order of subgroup is not prime'
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


        @staticmethod
        def make_schnorr_proof(system):
            """
            """
            return 0

        @staticmethod
        def make_schnorr_verify(system):
            """
            """
            return 1

        @staticmethod
        def make_chaum_pedersen_proof(system):
            """
            """
            return 2

        @staticmethod
        def make_chaum_pedersen_proof(system):
            """
            """
            return 3

        @staticmethod
        def make_keygen(system):
            """
            """
            return 4
