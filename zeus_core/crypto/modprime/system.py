from Crypto.Util.number import isPrime as is_prime
from gmpy2 import mpz, powmod, invert, mul
from functools import partial
from importlib import import_module

from ..abstracts import ElGamalCrypto
from .algebra import ModPrimeElement, ModPrimeSubgroup
from ..exceptions import (AlgebraError, WrongCryptoError, WeakCryptoError,
    InvalidKeyError)


V_MODULUS   = 'MODULUS: '
V_ORDER     = 'ORDER: '
V_GENERATOR = 'GENERATOR: '


class ModPrimeCrypto(ElGamalCrypto):
    """
    ElGamal cryptosystem over the group of r-residues mod p, p > 2 smooth prime.
    Defaults to r = 2, yielding the group of quadratic residues mod p
    """

    MIN_MOD_SIZE = 2048     # minimum modulus bitlength
    MIN_GEN_SIZE = 2000     # minimum generator bitlength

    __slots__ = ('__group', '__GroupElement',
        #
        # ~ Group params needed for mpz computations
        # ~ outside the group interface
        #
        '__modulus', '__order', '__generator')


    def __init__(self, modulus, primitive, root_order=2, prime_order=True,
            min_mod_size=None, min_gen_size=None, allow_weakness=False):
        """
        Assumes the provided primitive g_0 to be a primitive mod p, i.e.,
        a generator of the multiplicative group Z*_p or, equivalently, a
        primitive (p - 1)-root of 1 or, equivalently,

        g_0 ^ (p - 1) = 1 and g_0 ^ k != 1 for all 0 < k < p - 1
        """

        modulus = mpz(modulus)                                   # p
        primitive = ModPrimeElement(mpz(primitive), modulus)     # g_0
        root_order = mpz(root_order)                             # r

        # Resolve group
        try:
            group = ModPrimeSubgroup(modulus, root_order)
        except AlgebraError as err:
            raise WrongCryptoError(err)
        self.__group = group
        self.__modulus = group.modulus
        self.__order = group.order
        self.__GroupElement = ModPrimeElement

        #
        # ~ Resolve generator: Algebraic fact: given a primitive g_0 of Z*_p,
        # ~ where p > 2 smooth, and 1 < r < p - 1 with r | p - 1, then g_0 ^ r
        # ~ generates the q-subgroup of Z*_p, q = (p - 1)/r
        #
        generator = primitive ** root_order
        try:
            self.__group.set_generator(generator)
        except AlgebraError as err:
            raise WrongCryptoError(err)
        group = self.__group
        self.__generator = group.generator.value

        # Validate system
        __class__._validate_system(modulus, group.order, group.generator,
            root_order, prime_order, min_mod_size, min_gen_size, allow_weakness)


    @classmethod
    def _validate_system(cls, modulus, order, generator, root_order,
            prime_order, min_mod_size, min_gen_size, allow_weakness):
        """
        """
        if root_order==2 and modulus % 4 != 3:
            #
            # ~ Algebraic fact: the condition p = 3 mod 4 guarantees direct
            # ~ solvability of the congruence x ^ 2 = a (mod p), a E Z*_p,
            # ~ allowing for efficient verification of quadratic residues
            #
            err = "Provided modulus is not 3 mod 4"
            raise WrongCryptoError(err)
        if prime_order and not is_prime(order):
            err = "Order of the requested group is not prime"
            raise WrongCryptoError(err)
        if not allow_weakness:
            MIN_MOD_SIZE = min_mod_size or cls.MIN_MOD_SIZE
            if modulus.bit_length() < MIN_MOD_SIZE:
                err = f"Provided modulus is < {MIN_MOD_SIZE} bits long"
                raise WeakCryptoError(err)
            MIN_GEN_SIZE = min_gen_size or cls.MIN_GEN_SIZE
            if generator.bit_length < MIN_GEN_SIZE:
                err = f"Generator is < {MIN_GEN_SIZE} bits long"
                raise WeakCryptoError(err)


    @classmethod
    def _extract_config(cls, config):
        """
        :type config: dict
        :rtype: tuple
        """
        get = config.get

        modulus = config['modulus']
        primitive = config['primitive']
        root_order = get('root_order', 2)
        prime_order = get('prime_order', True)
        min_mod_size = get('min_mod_size', None)
        min_gen_size = get('min_gen_size', None)
        allow_weakness = get('allow_weakness', None)

        return (modulus, primitive, root_order, prime_order, min_mod_size,
            min_gen_size, allow_weakness)


    # --------------------------------- System ---------------------------------


    def parameters(self):
        """
        """
        serialized = {}

        serialized['modulus'] = int(self.__modulus)
        serialized['order'] = int(self.__order)
        serialized['generator'] = int(self.__generator)

        return serialized


    def hex_parameters(self):
        """
        Returns a serialization of the cryptosystem's parameters (the modulus p,
        order q and generator g), where the values appear as hexstrings
        """
        hexified = {}

        hexified['modulus'] = '%x' % self.__modulus
        hexified['order'] = '%x' % self.__order
        hexified['generator'] = '%x' % self.__generator

        return hexified


    def _parameters(self):
        """
        """
        __p = self.__modulus
        __q = self.__order
        __g = self.__generator

        return __p, __q, __g


    @property
    def group(self):
        """
        """
        return self.__group


    @property
    def GroupElement(self):
        """
        """
        return self.__GroupElement


    def validate_element(self, element):
        """
        """
        return element.contained_in(self.__group)


    def generate_keypair(self, private_key=None):
        """
        """
        __group = self.__group

        if private_key is None:
            private_key = __group.random_exponent(min=3)
        elif not 1 < private_key < self.__order:
            err = "Provided private key exceeds the allowed range"
            raise InvalidKeyError(err)
        else:
            private_key = mpz(private_key)

        public_key = __group.generate(private_key)              # y = g ^ x modp

        return private_key, public_key


    # ---------------- (De)serialization of algebraic entities -----------------


    def int_to_exponent(self, integer):
        """
        """
        return mpz(integer)


    def hex_to_exponent(self, hex_string):
        """
        """
        return mpz(hex_string, 16)


    def exponent_to_int(self, exponent):
        """
        """
        return int(exponent)


    def exponent_to_hex(self, exponent):
        """
        """
        return '%x' % exponent


    def int_to_element(self, integer):
        """
        """
        return self.__GroupElement(integer, self.__modulus)


    def hex_to_element(self, hex_string):
        """
        """
        return self.__GroupElement(mpz(hex_string, 16), self.__modulus)


    def encode_integer(self, integer):
        """
        """
        element = self.__group.encode_integer(integer)
        return element


    # ---------------------- Vote validation and signing -----------------------


    def mk_hex_labels(self):
        """
        """
        hex_p = V_MODULUS + '%x' % self.__modulus
        hex_q = V_ORDER + '%x' % self.__order
        hex_g = V_GENERATOR + '%x' % self.__generator

        return hex_p, hex_q, hex_g


    def check_labels(self, t08, t09, t10):
        """
        """
        return t08.startswith(V_MODULUS) and \
               t09.startswith(V_ORDER) and \
               t10.startswith(V_GENERATOR)


    def hexify_crypto_params(self, params):
        """
        """
        hex_p = V_MODULUS + '%x' % params['modulus']
        hex_q = V_ORDER + '%x' % params['order']
        hex_g = V_GENERATOR + '%x' % params['generator']

        return hex_p, hex_q, hex_g


    def unhexify_crypto_params(self, t08, t09, t10):
        """
        """
        params = {}

        hex_p = t08[len(V_MODULUS):]
        hex_q = t09[len(V_ORDER):]
        hex_g = t10[len(V_GENERATOR):]

        params['modulus'] = mpz(hex_p, 16)
        params['order'] = mpz(hex_q, 16)
        params['generator'] = mpz(hex_g, 16)

        return params


    # ------------------------------- Primitives -------------------------------


    # Schnorr protocol

    def _schnorr_proof(self, secret, public, *extras):
        """
        Schnorr protocol implementation from the prover's side (non-interactive)

        Returns ZK (Schnorr) proof-of-knowldge of the discrete logarithm
        x (`secret`) of y (`public`), with `*extras` to be used in the
        Fiat-Shamir heuristic

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

        proof = self.set_schnorr_proof(commitment, challenge, response)
        return proof


    def _schnorr_verify(self, proof, public, *extras):
        """
        Schnorr protocol implementation from the verifier's side (non-interactive)

        Validates the demonstrated (Schnorr) proof-of-knowledge `proof` of the
        discrete logarithm of y (`public`), with `*extras` assumed to have been
        used in the Fiat-Shamir heuristic

        :type proof: dict
        :type public: modPrimeElement
        :type *extras: mpz or int or ModPrimeElement
        """
        __group = self.__group

        # g ^ r, c, s
        commitment, challenge, response = self.extract_schnorr_proof(proof)

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


    # Chaum-Pedersen protocol

    def _chaum_pedersen_proof(self, ddh, z):
        """
        Chaum-Pedersen protocol implementation from the prover's side (non-interactive)

        Returns zero-knowledge proof (Chaum-Pedersen proof) that the provided 3-ple `ddh`
        is a DDH with respect to the generator g of the cryptosystem's underlying group,
        i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q

        :type ddh: (ModPrimeElement, ModPrimeElement, ModPrimeElement)
        :type z: mpz
        :rtype: dict
        """

        __group = self.__group

        u, v, w = ddh

        randomness = __group.random_exponent()

        g_commitment = __group.generate(randomness)                     # g ^ r
        u_commitment = u ** randomness                                  # u ^ r

        challenge = __group.fiatshamir(
            u, v, w,
            g_commitment,
            u_commitment)   # c = g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp

        response = __group.add_exponents(randomness, challenge * z)      # s = r + c * z  modq

        proof = self._set_chaum_pedersen_proof(g_commitment, u_commitment, challenge, response)
        return proof


    def _chaum_pedersen_verify(self, ddh, proof):
        """
        Chaum-Pedersen protocol implementation from the verifier's side (non-interactive)

        Verifies that the demonstrated `proof` proves knowledge that the provided 3-ple `ddh`
        is a DDH with respect to the generator g of the cryptosystem's underlying group, i.e.,
        of the form

                                (u, v, g ^ (x * z) modp)


        where u = g ^ x (modp), v = g ^ z (modp) with 0 <= x, z < q

        The provided `ddh` is of the form

                    (ModPrimeElement, ModPrimeElement, ModPrimeElement)

        and the provided `proof` of the form

        {
            'base_commitment': ModPrimeElement
            'message_commitment': ModPrimeElement
            'challenge': mpz
            'response': mpz
        }

        :type ddh: tuple
        :type proof: dict
        :rtype: bool
        """

        __group = self.__group

        u, v, w = ddh

        # g ^ r, u ^ r, c, s
        g_commitment, u_commitment, challenge, response =\
            self.extract_chaum_pedersen_proof(proof)

        # Check correctness of challenge:
        # c == g ^ ( H( p | g | q | u | v | w | g ^ r | u ^ r ) modq ) modp ?
        _challenge = __group.fiatshamir(
            u, v, w,
            g_commitment,
            u_commitment)

        if _challenge != challenge:
            return False

        # Verify prover's commitment to acclaimed randomness:
        # g ^ s == g ^ r * v ^ c  modp ?
        if __group.generate(response) != g_commitment * (v ** challenge):
            return False

        # Verify that the provided u is of the form g ^ (k * z) for some k (and
        # thus k = x due to prover's verified commitment to randomness r):
        # u ^ s == u ^ r * w ^ c  modp ?
        return u ** response == u_commitment * (w ** challenge)


    # Digital Signature Algorithm (low-level DSA)

    def _dsa_signature(self, exponent, private_key):
        """
        Returns and computes the DSA-signature

                {
                    'exponent': e,
                    'commitments': {
                        'c_1': (g ^ r modp) modq
                        'c_2': (e + x * c_1)/r modq
                    }
                }

        of the provided `exponent` e (assumed to be in the range {1, ..., q - 1})
        under the `private_key` x for a once used randmoness 1 < r < q

        :type exponent: mpz
        :type private_key: mpz
        :rtype: dict
        """
        __group = self.__group
        __q = self.__order

        randomness = __group.random_exponent()                           # 1 < r < q
        c_1 = __group.generate(randomness).value % __q                   # (g ^ r modp) modq

        exps = __group.add_exponents(exponent, mul(private_key, c_1))    # (e + x * c_1) modq
        r_inv = invert(randomness, __q)                                  # r ^ -1 modq
        c_2 = mul(exps, r_inv) % __q                                     # (e + x * c_1)/r modq

        signature = self.set_dsa_signature(exponent, c_1, c_2)
        return signature


    def _dsa_verify(self, exponent, signature, public_key):
        """
        Verifies that the provided DSA-signature `signature` signs the given
        `exponent` under the given `public_key`

        :type exponent: mpz
        :type signature: dict
        :type public_key: ModPrimeElement
        :rtype: bool
        """
        __group = self.__group
        __q = self.__order

        _, c_1, c_2 = self.extract_dsa_signature(signature)

        # Commitments' validity check
        for c in (c_1, c_2):
            if not 0 < c < __q:
                return False

        # Proceed to signature validation

        c_2_inv = invert(c_2, __q)                                      # c_2 ^ -1 modq

        v_1 = mul(exponent, c_2_inv) % __q                              # (e + c_2 ^ -1) modq
        v_2 = mul(c_1, c_2_inv) % __q                                   # (v_1 * c_2 ^ -1) modq

        element = (__group.generate(v_1) * public_key ** v_2).value     # (g ^ v_1 * y ^ v_2) modp

        # ((g ^ v_1 * y ^ v_2) modp) modq == c_1 ?
        return element % __q == c_1


    # Text-message signatures (high-level DSA)

    def sign_text_message(self, message, private_key):
        """
        Signs the provided `message` m with the provided `private_key` x,
        returning the signed message

                {
                    'message': m,
                    'signature': {
                        'exponent': H(m),
                        'commitments': {
                            'c_1': (g ^ r modp) modq,
                            'c_2': (H(m) + x * c_1)/r modq
                        }
                    }
                }

        for a once used randomness 1 < r < q.

        .. note:: The original message m gets hashed as H(m) before
        being signed for defence against existential forgery.

        :type message: str
        :type private_key: mpz
        :rtype: dict
        """
        hashed_message = self.__group.exponent_from_texts(message)
        signature = self._dsa_signature(hashed_message, private_key)

        signed_message = self.set_signed_message(message, signature)
        return signed_message


    def verify_text_signature(self, signed_message, public_key):
        """
        Given a signed message `signed_message`, verifies the attached signature
        under the provided public key `public_key`

        :type signed_message: dict
        :type public_key: GroupElement
        :rtype: bool
        """
        message, signature = self.extract_signed_message(signed_message)

        # Verify signature
        hashed_message = self.__group.exponent_from_texts(message)              # H(m)
        verified = self._dsa_verify(hashed_message, signature, public_key)

        return verified


    # El-Gamal encryption/decryption

    def encrypt(self, element, public_key, randomness=None, get_secret=False):
        """
        ElGamal encryption

        Computes and returns the ciphertext

                    {
                        'alpha': g ^ r (modp)
                        'beta': m * y ^ r (mod p)
                    }

        of the provided element m, where the provided public key is the
        receiver's public key y and 1 < r < q a once used randomness

        :type element: ModPrimeElement
        :type public_key: ModPrimeElement
        :type randomness: mpz
        :type get_secret: bool
        :rtype: dict or (dict, mpz)
        """
        __group = self.__group

        if randomness is None:
            randomness = __group.random_exponent()

        alpha = __group.generate(randomness)            # g ^ r (modp)
        beta = element * public_key ** randomness       # m * y ^ r (modp)

        ciphertext = self.set_ciphertext(alpha, beta)

        if get_secret:
            return ciphertext, randomness
        return ciphertext


    def decrypt(self, ciphertext, private_key):
        """
        Standard ElGamal decryption

        .. note:: this function is not used by zeus. It is here included
        for completeness of the cryptossytem and testing purposes. For
        actual use see the `.decrypt_with_decryptor()` method.

        Decrypts the provided ciphertext

                            {'alpha': a, 'beta': b}

        under the provided private key x, returning the original element

                                (a ^ x) ^ -1 * b

        :type ciphertext: dict
        :type private_key: mpz
        :rtype: ModPrimeElement
        """
        alpha, beta = self.extract_ciphertext(ciphertext)
        original = (alpha ** private_key).inverse * beta        # (alpha ^ x) ^ -1 * beta (modp)

        return original


    def reencrypt(self, ciphertext, public_key, randomness=None, get_secret=False):
        """
        Re-encryption of ciphertext

        .. note:: This function is not used by zeus. It is here included for
        testing and explanatory purposes. For actual use see the homonymous
        mixnet method instead.

        Given a ciphertext

                    {
                        'alpha': a,
                        'beta': b
                    }

        and an element `public_key` y, computes and returns the ciphertext

                    {
                        'alpha': a * g ^ r      (modp)
                        'beta': b * y ^ r       (modp)
                    }

        .. note:: (Special case with fixed public key) Given the ElGamal encryption

                    {
                        'alpha': g ^ r_0        (modp)
                        'beta': m * y ^ r_0     (modp)
                    }

        of an original message m under the public key y, re-encrypting n times under
        the same key y and successive randomnesses r_1, ..., r_n yields

                    {
                        'alpha': g ^ (r_0 + r_1 + ... + r_n)        (modp)
                        'beta': m * y ^ (r_0 + r_1 + ... + r_n)     (modp)
                    }

        i.e., is equivalent to encrypting once with randomness r_0 + r_1 + ... + r_n

        :type ciphertext: dict
        :type public_key: ModPrimeElement
        :type randomness: mpz
        :type get_secret: bool
        :rtype: dict or (dict, mpz)
        """
        __group = self.__group

        if randomness is None:
            randomness = __group.random_exponent(min=3)

        alpha, beta = self.extract_ciphertext(ciphertext)

        alpha = alpha * __group.generate(randomness)                # a * g ^ r
        beta = beta * public_key ** randomness                      # b * y ^ r

        ciphertext = self.set_ciphertext(alpha, beta)

        if get_secret:
            return ciphertext, randomness
        return ciphertext


    def decrypt_with_decryptor(self, ciphertext, decryptor):
        """
        Given the ciphertext `ciphertext`

                            {'alpha': a, 'beta': b}

        and `decryptor` d, computes and returns the element

                                  d ^ -1 * b

        :type ciphertext: dict
        :type decryptor: ModPrimeElement
        :rtype: ModPrimeElement

        .. note:: specializes to standard ElGamal decryption (`.decrypt()`) if
        `decryptor` is a ^ x, where x is the private key used at ecnryption
        """
        _, beta = self.extract_ciphertext(ciphertext)
        encoded = decryptor.inverse * beta                      # decryptor ^ -1 * beta (modp)

        return encoded


    def decrypt_with_randomness(self, ciphertext, public, secret):
        """
        Given the ciphertext `ciphertext`

                            {'alpha': a, 'beta': b},

        a group element `public` y and an exponent `secret` x, computes and
        returns the element

                          (y ^ x) ^ -1 * b - 1 (mod p)

        if (y ^ x) ^ -1 * b happens to be contained in the cryptosystem's
        underlying group; otherwise the element

                    (-(y ^ x) ^ -1 * b (mod p)) - 1 (mod p)

        is returned.

        :type public: ModPrimeElement
        :type ciphertext: dict
        :type secret: mpz
        :rtype: ModPrimeElement
        """
        _, beta = self.extract_ciphertext(ciphertext)
        encoded = (public ** secret).inverse * beta             # (y ^ x) ^ -1 * beta (modp)
        decoded = self.__group.decode_with_randomness(encoded)

        return decoded
