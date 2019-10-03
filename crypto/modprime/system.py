import Crypto
from Crypto.Util.number import isPrime as is_prime
from gmpy2 import mpz, powmod, invert, mul
from functools import partial
from importlib import import_module

from .algebra import ModPrimeElement, ModPrimeSubgroup

from ..abstracts import ElGamalCrypto
from ..exceptions import (AlgebraError, WrongCryptoError, WeakCryptoError,
    InvalidKeyError, InvalidVoteError, InvalidSignatureError, InvalidFactorError,
    BallotDecryptionError)
# from elections.constants import V_MODULUS, V_ORDER, V_GENERATOR
from utils import hash_texts, hash_encode, hash_decode, extract_value

V_MODULUS   = 'MODULUS: '
V_ORDER     = 'ORDER: '
V_GENERATOR = 'GENERATOR: '

class ModPrimeCrypto(ElGamalCrypto):
    """
    ElGamal cryptosystem over the group of r-residues mod p, p > 2 prime.
    Defaults to r = 2, yielding the group of quadratic residues mod p
    """

    MIN_MOD_SIZE = 2048
    MIN_GEN_SIZE = 2000

    __slots__ = ('__group', '__GroupElement',

        # Group params included for mpz computations outside the group interface
        '__modulus', '__order', '__generator')


    def __init__(self, modulus, primitive, root_order=2, prime_order=True,
            min_mod_size=None, min_gen_size=None, allow_weakness=False):
        """
        Assumes the provided `primitive` g_0 to be a primitive mod p, i.e.,
        a generator of the multiplicative group Z*_p or, equivalently, a
        primitive (p - 1)-root of 1, i.e.,

        g_0 ^ (p - 1) = 1 and g_0 ^ k != 1 for all 0 < k < p - 1

        :type modulus: int
        :type primitive: int
        :type root_order: int
        :type prime_order: bool
        :type min_mod_size: int
        :type min_gen_size: int
        :type allow_weakness: bool
        """

        modulus = mpz(modulus)                                   # p
        primitive = ModPrimeElement(mpz(primitive), modulus)     # g_0
        root_order = mpz(root_order)                             # r

        # Resolve group
        try:
            group = ModPrimeSubgroup(modulus, root_order)
        except AlgebraError:
            raise

        self.__group = group
        self.__modulus = group.modulus
        self.__order = group.order

        self.__GroupElement = ModPrimeElement

        # Resolve generator

        # Algebraic fact: given a primitive g_0 of Z*_p, p > 2 smooth, and 1 < r < p - 1
        # with r | p - 1, then g_0 ^ r generates the q-subgroup of Z*_p, q = (p - 1)/r
        generator = primitive ** root_order

        try:
            self.__group.set_generator(generator)
        except AlgebraError:
            raise
        else:
            group = self.__group

        self.__generator = group.generator.value

        # Validate system
        self.__class__._validate_system(modulus, group.order, group.generator,
            root_order, prime_order, min_mod_size, min_gen_size, allow_weakness)

    @classmethod
    def _validate_system(cls, modulus, order, generator,
        root_order, prime_order, min_mod_size, min_gen_size, allow_weakness):
        """
        :type modulus: mpz
        :type order: mpz
        :type generator: ModPrimElement
        :type root_order: mpz
        :type prime_order: bool
        :type min_mod_size: int
        :type min_gen_size: int
        :allow_weakness: bool
        """
        if root_order==2 and modulus % 4 != 3:
            # Algebraic fact: the condition p = 3 mod 4 guarantees direct
            # solvability of the congruence x ^ 2 = a (mod p), a E Z*_p,
            # allowing for efficient verification of quadratic residues
            err = 'Provided modulus is not 3 mod 4'
            raise WrongCryptoError(err)

        if prime_order and not is_prime(order):
            err = 'Order of the requested group is not prime'
            raise WrongCryptoError(err)

        if not allow_weakness:

            MIN_MOD_SIZE = min_mod_size or cls.MIN_MOD_SIZE
            if modulus.bit_length() < MIN_MOD_SIZE:
                err = 'Provided modulus is < %d bits long' % MIN_MOD_SIZE
                raise WeakCryptoError(err)

            MIN_GEN_SIZE = min_gen_size or cls.MIN_GEN_SIZE
            if generator.bit_length < MIN_GEN_SIZE:
                err = 'Generator is < %d bits long' % MIN_GEN_SIZE
                raise WeakCryptoError(err)

    @classmethod
    def _extract_config(cls, config):
        """
        :type config: dict
        :rtype: tuple
        """
        modulus = config['modulus']
        primitive = config['primitive']
        root_order = config['root_order'] if 'root_order' in config else 2
        prime_order = config['prime_order'] if 'prime_order' in config else True
        min_mod_size = config['min_mod_size'] if 'min_mod_size' in config else None
        min_gen_size = config['min_gen_size'] if 'min_gen_size' in config else None
        allow_weakness = config['allow_weakness'] if 'allow_weakness' in config else None

        return (modulus, primitive, root_order, prime_order, min_mod_size,
            min_gen_size, allow_weakness)


    # ------------------------------ Cryptosystem ------------------------------


    def parameters(self):
        """
        Returns the modulus p, order q and fixed generator g of the underlying
        group as a dictionary with integer values

        :rtype: dict
        """
        __p, __q, __g = self._parameters()

        return {'modulus': int(__p), 'order': int(__q), 'generator': int(__g)}

    def _parameters(self):
        """
        Returns the modulus p, order q and fixed generator g of the underlying
        group as a tuple of the form (mpz, mpz, mpz)

        :rtype: tuple
        """
        __p = self.__modulus
        __q = self.__order
        __g = self.__generator

        return __p, __q, __g

    def to_exponent(self, integer):
        """
        :type integer: int
        :rtype: ModPrimeElement
        """
        return mpz(integer)

    def encode_integer(self, integer):
        """
        :type integer: int
        :rtype: ModPrimeElement
        """
        element = self.__group.encode_integer(integer)
        return element


    def textify_params(self, crypto_params):
        t07 = V_MODULUS + '%s' % str(crypto_params['modulus'])
        t08 = V_ORDER + '%s' % str(crypto_params['order'])
        t09 = V_GENERATOR + '%s' % str(crypto_params['generator'])
        return t07, t08, t09

    def verify_textified_params(self, t07, t08, t09):
        """
        """
        return t07.startswith(V_MODULUS) \
            and t08.startswith(V_ORDER) and t09.startswith(V_GENERATOR)

    @property
    def group(self):
        """
        Returns the underlying group of the cryptosystem

        :rtype: ModPrimeSubgroup
        """
        return self.__group

    @property
    def GroupElement(self):
        """
        Type of the cryptosystem's gorup objects

        :rtype: class
        """
        return self.__GroupElement


    # ----------------------------- Key Management -----------------------------

    ######################################################################
    #                                                                    #
    #    By keypair is meant a dictionary of the form                    #
    #                                                                    #
    #    {                                                               #
    #        'private': mpz,                                             #
    #        'public': {                                                 #
    #            'value': ModPrimeElement,                               #
    #            'proof': ...                                            #
    #        }                                                           #
    #    }                                                               #
    #                                                                    #
    #   where tha value of `proof` is either `None` or a Schnorr-proof   #
    #                                                                    #
    ######################################################################

    def keygen(self, private_key=None, schnorr=True):
        """
        Generates and returns a keypair

        If `shnorr` is left to its default value `True`, the public part
        will include proof-of-knowledge of the private part

        :type private_key: mpz or int
        :type schnorr: bool
        :rtype: dict
        """
        __group = self.__group

        if private_key is None:
            private_key = __group.random_exponent(min=3)

        elif not 1 < private_key < self.__order:
            err = 'Provided private key exceeds the allowed range'
            raise InvalidKeyError(err)
        else:
            private_key = mpz(private_key)               # in case int was given

        public_key = __group.generate(private_key)              # y = g ^ x modp

        proof = None
        if schnorr:
            proof = self._schnorr_proof(private_key, public_key)

        public_key = self._set_public_key(public_key, proof)
        keypair = self._set_keypair(private_key, public_key)

        return keypair


    #####################################################################
    #                                                                   #
    #    By public-key is meant a dictionary of the form                #
    #                                                                   #
    #    {                                                              #
    #        'value': ModPrimeElement,                                  #
    #        'proof': ...                                               #
    #    }                                                              #
    #                                                                   #
    #    where the value of 'proof' is either None or a Schnorr-proof   #
    #                                                                   #
    #####################################################################

    def validate_public_key(self, public_key):
        """
        Verifies that the 'proof' field proves knowledge of the private counterpart

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

        return self._schnorr_verify(proof=proof, public=public_key)

    def set_public_key_from_value(self, value, proof=None):
        """
        :type value: int or mpz
        :type proof: dict
        :rtype: dict
        """
        public_key = {
            'value': self.__GroupElement(mpz(value), self.__modulus),
            'proof': proof
        }
        return public_key


    # ------------------------------- Primitives -------------------------------


    # Schnorr protocol

    ############################################################
    #                                                          #
    #    By Schnorr-proof is meant a dictionary of the form    #
    #                                                          #
    #    {                                                     #
    #       'commitment': ModPrimeElement                      #
    #       'challenge': mpz                                   #
    #       'response': mpz                                    #
    #    }                                                     #
    #                                                          #
    ############################################################

    def _schnorr_proof(self, secret, public, *extras):
        """
        Implementation of Schnorr protocol from the prover's side (non-interactive)

        Returns proof-of-knowldge (Schnorr-proof) of the discrete logarithm x (`secret`)
        of y (`public`), with `*extras` being used in the Fiat-Shamir heuristic

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
        Implementation of Schnorr protocol from the verifier's side (non-interactive)

        Validates the demonstrated (Schnorr) proof-of-knowledge `proof` of the discrete
        logarithm of y (`public`), with `*extras` assumed to have been used in the
        Fiat-Shamir heuristic

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

    ###################################################################
    #                                                                 #
    #    By Chaum-Pedersen proof is meant a dictionary of the form    #
    #                                                                 #
    #    {                                                            #
    #        'base_commitment': ModPrimeElement                       #
    #        'message_commitment': ModPrimeElement                    #
    #        'challenge': mpz                                         #
    #        'response': mpz                                          #
    #    }                                                            #
    #                                                                 #
    ###################################################################

    def _chaum_pedersen_proof(self, ddh, z):
        """
        Implementation of Chaum-Pedersen protocol from the prover's side (non-interactive)

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
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Verifies that the demonstrated `proof` proves knowledge that the provided 3-ple `ddh`
        is a DDH with respect to the generator g of the cryptosystem's underlying group, i.e., of
        the form

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
            self._extract_chaum_pedersen_proof(proof)

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
        # thus k = x due to prover's verified commitment to randomness r):
        # u ^ s == u ^ r * w ^ c  modp ?
        return u ** response == u_commitment * (w ** challenge)


    # Digital Signature Algorithm

    ############################################################
    #                                                          #
    #    By DSA-signature is meant a dictionary of the form    #
    #                                                          #
    # 	{                                                      #
    #       'exponent': mpz,                                   #
    #       'commitments': {                                   #
    #           'c_1': mpz,                                    #
    #           'c_2': mpz                                     #
    #       }                                                  #
    # 	}                                                      #
    #                                                          #
    ############################################################

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

        # Extract data from signature
        _, c_1, c_2 = self._extract_dsa_signature(signature)

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


    # Text-message signatures

    #####################################################################
    #                                                                   #
    #    By signed message is meant a dictionary of the form            #
    #                                                                   #
    #    {                                                              #
    #        'message': str,                                            #
    #        'signature': {                                             #
    #            'exponent': mpz,                                       #
    #            'commitments': {                                       #
    #               'c_1': mpz,                                         #
    #               'c_2': mpz                                          #
    #             }                                                     #
    #         }                                                         #
    #     }                                                             #
    #                                                                  #
    #####################################################################

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

        .. note:: The original message m gets hashed as H(m) before being signed for
        defence against existential forgery.

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
        :type public_key: dict
        :rtype: bool
        """
        message, signature = self._extract_message_signature(signed_message)
        public_key = self.get_key(public_key)

        # Verify signature
        hashed_message = self.__group.exponent_from_texts(message)              # H(m)
        verified = self._dsa_verify(hashed_message, signature, public_key)

        return verified


    # El-Gamal encryption and decryption

    #########################################################
    #                                                       #
    #    By ciphertext is meant a dictionary of the form    #
    #                                                       #
    #    {                                                  #
    #        'alpha': ModPrimeElement                       #
    #        'beta': ModPrimeElement                        #
    #    }                                                  #
    #                                                       #
    #########################################################

    def _encrypt(self, element, public_key, randomness=None, get_secret=False):
        """
        ElGamal encryption

        Computes and returns the ciphertext

        {
            'alpha': g ^ r (modp)
            'beta': m * y ^ r (mod p)
        }

        of the provided `element` m, where `public_key` is the receiver's
        public key y and 1 < r < q a once used randomness

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

    def _reencrypt(self, ciphertext, public_key, randomness=None, get_secret=False):
        """
        Re-encryption of ciphertext

        .. note:: This function is not used by zeus. It is here included for
        testing and explanatory purposes. For actual use see the homonymous
        mixnet method instead.

        Given a ciphertext `ciphertext`

        {'alpha': a, 'beta': b}

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

    def prove_encryption(self, ciphertext, randomness):
        """
        Generates proof-of-knowledge of the `randomness` r involved in the
        ElGamal encryption yielding the provided ciphertext `ciphertext`

        :type ciphertext: dict
        :type randomness: mpz
        :rtype: dict
        """
        alpha, beta = self.extract_ciphertext(ciphertext)
        proof = self._schnorr_proof(randomness, alpha, beta)

        return proof

    def verify_encryption(self, ciphertext_proof):
        """
        Assuming a dictionary

        {'ciphertext': ..., 'proof': ...}

        verifies that 'proof' proves knowledge of the randomness used in the
        ElGamal encryption that yields 'ciphertext'

        :type ciphertext_proof: dict
        :rtype: bool
        """
        ciphertext, proof = self.extract_ciphertext_proof(ciphertext_proof)
        alpha, beta = self.extract_ciphertext(ciphertext)
        verified = self._schnorr_verify(proof, alpha, beta)

        return verified

    def _decrypt(self, ciphertext, private_key):
        """
        Standard ElGamal decryption

        .. note:: this function is not used by zeus. It is here included
        for completeness of the cryptossytem and testing purposes. For
        actual use see the `.decrypt_with_decryptor()` method.

        Decrypts the provided ciphertext `ciphertext`

        {'alpha': a, 'beta': b}

        under the provided `private_key` x, returning the original element

        (a ^ x) ^ -1 * b

        :type ciphertext: dict
        :type private_key: mpz
        :rtype: ModPrimeElement
        """
        alpha, beta = self.extract_ciphertext(ciphertext)
        original = (alpha ** private_key).inverse * beta        # (alpha ^ x) ^ -1 * beta (modp)

        return original

    def _decrypt_with_decryptor(self, ciphertext, decryptor):
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

    def _decrypt_with_randomness(self, ciphertext, public, secret):
        """
        Given the ciphertext `ciphertext`

        {'alpha': a, 'beta': b},

        a group element `public` y and an exponent `secret` x, computes and
        returns the element

        (y ^ x) ^ -1 * b - 1 (mod p)

        if (y ^ x) ^ -1 * b happens to be contained in the cryptosystem's
        underlying group; otherwise the element

        (-(y ^ x) ^ -1 * b (mod p)) - 1 (mod p)

        is returned

        :type public: ModPrimeElement
        :type ciphertext: dict
        :type secret: mpz
        :rtype: ModPrimeElement
        """
        _, beta = self.extract_ciphertext(ciphertext)
        encoded = (public ** secret).inverse * beta             # (y ^ x) ^ -1 * beta (modp)
        decoded = self.group.decode_with_randomness(encoded)

        return decoded


    # ----------------------------- Elections API -----------------------------

    # Creating

    def create_zeus_keypair(self, zeus_secret_key=None):
        """
        Creates and returns a key pair for zeus

        :type zeus_secret_key: mpz
        :rtype: dict
        """
        zeus_keypair = self.keygen(zeus_secret_key)
        return zeus_keypair

    def generate_trustees(self, nr_trustees):
        """
        :type nr_trustees: int
        :rtype: list[dict]
        """
        keypairs = [self.keygen() for _ in range(nr_trustees)]
        trustees = [self._get_public(keypair) for keypair in keypairs]
        return trustees

    def reprove_trustee(self, trustee_keypair):
        """
        :type trustee_keypair: dict
        :rtype: dict
        """
        private_key, public_key = self.extract_keypair(trustee_keypair)
        public_key = self.get_value(public_key)
        proof = self._schnorr_proof(private_key, public_key)
        return proof

    def compute_election_key(self, trustees, zeus_keypair):
        """
        Computes and returns the election public key

        :type trustees: list[dict]
        :type zeus_keypair: dict
        :rtype: dict
        """
        public_shares = self.get_public_shares(trustees)
        zeus_public_key = self._get_public_value(zeus_keypair)
        combined = self._combine_public_keys(zeus_public_key, public_shares)
        election_key = self._set_public_key(combined)
        return election_key

    def validate_election_key(self, election_key, trustees, zeus_keypair):
        """
        :type election_key: dict
        :type trustees: list[dict]
        :type zeus_keypair: dict
        :rtype: bool
        """
        election_key = self.get_value(election_key)
        test_key = self.compute_election_key(trustees, zeus_keypair)
        return election_key == self.get_value(test_key)

    # Voting

    def vote(self, election_key, voter, plaintext,
                audit_code=None, publish=None):
        """
        Generates and returns an encrypted vote from the encoded plaintext

        :type election_key: dict
        :type voter:
        :type plaintext: int
        :type audit_code:
        :publish: None
        :rtype: dict
        """
        election_key = self.get_value(election_key)
        encoded_plaintext = self.encode_integer(plaintext)
        ciphertext, randomness = self._encrypt(encoded_plaintext, election_key,
            get_secret=True)

        proof = self.prove_encryption(ciphertext, randomness)

        encrypted = self.set_ciphertext_proof(ciphertext, proof)
        fingerprint = self.make_fingerprint(encrypted)

        vote = self.set_vote(voter, encrypted, fingerprint, audit_code, publish, randomness)
        return vote

    def validate_submitted_vote(self, vote):
        """
        Checks if the vote's fingerprint is correct, returning the fingerprint
        in this case; otherwise an exception gets raised.

        :type vote: dict
        :rtype: bytes
        """
        _, encrypted, fingerprint, _, _, _, _, _, _ = self.extract_vote(vote)

        if not self.verify_encryption(encrypted):
            err = 'Invalid encryption proof'
            raise InvalidVoteError(err)

        if fingerprint != self.make_fingerprint(encrypted):
            err = 'Invalid fingerprint'
            raise InvalidVoteError(err)

        return fingerprint

    def sign_vote(self, vote, comments, election_key, zeus_keypair, trustees, choices):
        """
        choices (candidates) format example:

            ['Party-A: 0-2, 0', 'Party-A: Candidate-0000',
            'Party-B: generator0-2, 1', 'Party-B: Candidate-0001']

        :type vote: dict
        :type comments:
        :type election_key: dict
        :type zeus_keypair: dict
        :type trustees: list[dict]
        :type choices: list[str]
        :rtype:
        """
        __p, __q, __g = self._parameters()

        election_key = self.get_value(election_key)

        zeus_private_key, zeus_public_key = self.extract_keypair(zeus_keypair)
        zeus_public_key = self.get_value(zeus_public_key)

        _, encrypted, fingerprint, _, _, previous, index, status, _ = self.extract_vote(vote)

        alpha, beta, commitment, challenge, response = self.get_fingerprint_params(encrypted)

        trustees = [self.get_value(trustee) for trustee in trustees]

        m00 = status if status is not None else 'NONE'
        m01 = '%s%s' % (V_FINGERPRINT, fingerprint)
        m02 = '%s%s' % (V_INDEX, ('%d' % index) if index is not None else 'NONE')
        m03 = '%s%s' % (V_PREVIOUS, (previous,)) 	# '%s%s' % (V_PREVIOUS, previous)
        m04 = '%s%s' % (V_ELECTION, str(election_key))
        m05 = '%s%s' % (V_ZEUS_PUBLIC, str(zeus_public_key))
        m06 = '%s%s' % (V_TRUSTEES, ' '.join(str(_) for _ in trustees))
        m07 = '%s%s' % (V_CANDIDATES, ' % '.join('%s' % _.encode('utf-8') for _ in choices))
        m08 = '%s%s' % (V_MODULUS, str(__p))
        m09 = '%s%s' % (V_ORDER, str(__q))
        m10 = '%s%s' % (V_GENERATOR, str(__g))
        m11 = '%s%s' % (V_ALPHA, str(alpha))
        m12 = '%s%s' % (V_BETA, str(beta))
        m13 = '%s%s' % (V_COMMITMENT, str(commitment))
        m14 = '%s%s' % (V_CHALLENGE, str(challenge))
        m15 = '%s%s' % (V_RESPONSE, str(response))
        m16 = '%s%s' % (V_COMMENTS, (comments,))

        message = '\n'.join((m00, m01, m02, m03, m04, m05, m06, m07,\
            m08, m09, m10, m11, m12, m13, m14, m15, m16))

        signed_message = self.sign_text_message(message, zeus_private_key)
        message, exponent, c_1, c_2 = self.extract_signed_message(signed_message)
        exponent, c_1, c_2 = str(exponent), str(c_1), str(c_2)

        vote_signature = message
        vote_signature += '\n-----------------\n'
        vote_signature += '%s\n%s\n%s\n' % (exponent, c_1, c_2)

        return vote_signature

    def verify_vote_signature(self, vote_signature):
        """
        Returns `True` if verified, otherwise raises `InvalidSignatureError`

        :type vote_signature: str
        :rtype: bool
        """
        message, _, exponent, c_1, c_2, _ = vote_signature.rsplit('\n', 5)

        (m00, m01, m02, m03, m04, m05, m06, m07, m08, m09,
            m10, m11, m12, m13, m14, m15, m16) = message.split('\n', 16)

        # Check signature structure

        if not ((m00.startswith(V_CAST_VOTE) or
            m00.startswith(V_AUDIT_REQUEST) or
            m00.startswith(V_PUBLIC_AUDIT) or
            m00.startswith(V_PUBLIC_AUDIT_FAILED) or
            m00.startswith('NONE')) or
            not m01.startswith(V_FINGERPRINT) or
            not m02.startswith(V_INDEX) or
            not m03.startswith(V_PREVIOUS) or
            not m04.startswith(V_ELECTION) or
            not m05.startswith(V_ZEUS_PUBLIC) or
            not m06.startswith(V_TRUSTEES) or
            not m07.startswith(V_CANDIDATES) or
            not m08.startswith(V_MODULUS) or
            not m09.startswith(V_ORDER) or
            not m10.startswith(V_GENERATOR) or
            not m11.startswith(V_ALPHA) or
            not m12.startswith(V_BETA) or
            not m13.startswith(V_COMMITMENT) or
            not m14.startswith(V_CHALLENGE) or
            not m15.startswith(V_RESPONSE) or
            not m16.startswith(V_COMMENTS)):
            err = 'Invalid vote signature structure'
            raise InvalidSignatureError(err)

        # Extract data

        status = m00
        fingerprint = m01[len(V_FINGERPRINT):]

        index_str = m02[len(V_INDEX):]
        if index_str == 'NONE':
            index = None
        elif index_str.isdigit():
            index = int(index_str)
        else:
            err = "Invalid vote index '%s'" % index_str
            raise InvalidSignatureError(err)

        previous = m03[len(V_PREVIOUS):]

        zeus_public_key = mpz(m05[len(V_ZEUS_PUBLIC):])
        zeus_public_key = self.set_public_key_from_value(zeus_public_key)

        _m06 = m06[len(V_TRUSTEES):]
        trustess = [int(_) for _ in _m06.split(' ')] if _m06 else []

        _m07 = m07[len(V_CANDIDATES):]
        candidates = _m07.split(' % ')

        modulus = mpz(m08[len(V_MODULUS):])
        order = mpz(m09[len(V_ORDER):])
        generator = mpz(m10[len(V_GENERATOR):])

        alpha = ModPrimeElement(mpz(m11[len(V_ALPHA):]), self.__modulus)
        beta = ModPrimeElement(mpz(m11[len(V_BETA):]), self.__modulus)

        commitment = mpz(m11[len(V_COMMITMENT):])
        challenge = mpz(m11[len(V_CHALLENGE):])
        response = mpz(m12[len(V_RESPONSE):])

        comments = m16[len(V_COMMENTS):]

        # Retrieve signed message

        exponent = mpz(exponent)
        c_1 = mpz(c_1)
        c_2 = mpz(c_2)
        signed_message = self.set_signed_message(message,
            signature=self.set_dsa_signature(exponent, c_1, c_2))

        # Validate signature or raise exception otherwise
        if not self.verify_text_signature(signed_message, zeus_public_key):
            err = 'Invalid vote signature'
            raise InvalidSignatureError(err)

        # Verify encryption proof or raise exception otherwise
        ciphertext = self.set_ciphertext(alpha, beta)
        proof = self.set_schnorr_proof(commitment, challenge, response)
        encrypted = self.set_ciphertext_proof(ciphertext, proof)
        # if index is not None and not self.verify_encryption(encrypted):
        if (index is not None and not self.verify_encryption(encrypted)):
            err = 'Invalid vote encryption'
            raise InvalidSignatureError(err)

        return True

    def verify_audit_votes(self, election_key, choices, votes=None, audit_reqs=None):
        """
        :type election_key: dict
        :type choices:
        :type votes:
        :type audit_reqs:
        :rtype: (list, list)
        """
        missing = []
        failed = []

        add_plaintext = 1
        nr_candidates = len(choices)
        max_encoded = gamma_encoding_max(nr_candidates)

        for vote in votes:
            _, encrypted, _, _, voter_secret, _, _, _, _ = self.extract_vote(vote)

            if not voter_secret:
                missing.append(vote)
                continue
            if not self.verify_encryption(encrypted):
                failed.append(vote)
                continue

            alpha_vote, _, _, _, _ = self.get_fingerprint_params(encrypted)
            alpha = self.group.generate(voter_secret)

            if alpha != alpha_vote:
                failed.append(vote)
                continue

            encoded = self._decrypt_with_randomness(election_key,
                ciphertext, voter_secret)

            if encoded.value > max_encoded.value:
                failed.append(vote)
            if add_plaintext:
                vote['plaintext'] = encoded.value

        return missing, failed


    def get_public_shares(self, trustees):
        """
        Extracts public keys of the provided trustees as group elements
        and returns them in a list

        :type trustees: list[dict]
        :rtype: list[ModPrimeElement]
        """
        get_key = self.get_key
        public_shares = [get_key(public_key) for public_key in trustees]
        return public_shares

    def _combine_public_keys(self, initial, public_keys):
        """
        Assuming the provided keys in the form of group elements, computes
        and returns their product

        :type initial: ModPrimeElement
        :type public_keys: list[ModPrimeElement]
        :rtype: ModPrimeElement
        """
        combined = initial
        for public_key in public_keys:
            combined = combined * public_key
        return combined

    def set_vote(self, voter, encrypted, fingerprint, audit_code=None, publish=None,
            voter_secret=None, previous=None, index=None, status=None, plaintext=None):
        """
        :type voter:
        :type encrypted: dict
        :type fingerprint: bytes
        :type audit_code:
        :type publish:
        :type voter_sercret:
        :type previous:
        :type index:
        :type status:
        :type plaintext: int
        :rtype: dict
        """
        vote = {}

        vote['voter'] = str(voter)
        vote['encrypted'] = encrypted
        vote['fingerprint'] = hash_decode(fingerprint)

        if audit_code:
            vote['audit_code'] = int(audit_code)
        if publish:
            vote['voter_secret'] = str(voter_secret)    # str(int(voter_secret))
        if previous:
            vote['index'] = str(index)
        if status:
            vote['status'] = status
        if plaintext:
            vote['plaintext'] = str(plaintext)

        return vote

    def extract_vote(self, vote):
        """
        :type vote: dict
        :rtype: dict
        """
        voter = vote['voter']
        encrypted = vote['encrypted']
        fingerprint = hash_encode(vote['fingerprint'])

        audit_code = extract_value(vote, 'audit_code', int)
        voter_secret = extract_value(vote, 'voter_secret', mpz)

        previous = None
        if 'previous' in vote.keys():
            previous = hash_encode(vote['previous'])

        index = extract_value(vote, 'index', int)
        status = extract_value(vote, 'status', str)

        cast = partial(self.__GroupElement, modulus=self.__modulus)
        plaintext = extract_value(vote, 'plaintext', cast)

        return voter, encrypted, fingerprint, audit_code,\
            voter_secret, previous, index, status, plaintext

    def get_fingerprint_params(self, ciphertext_proof):
        """
        Prepares fignerprint parameters out of a dictionary of the form

        {'ciphertext': dict, 'proof': dict}

        :type ciphertext_proof: dict
        :rtype: (ModPrimeElement, ModPrimeElement, ModPrimeElement, mpz, mpz, mpz)
        """
        ciphertext, proof = self.extract_ciphertext_proof(ciphertext_proof)
        alpha, beta = self.extract_ciphertext(ciphertext)
        commitment, challenge, response = self.extract_schnorr_proof(proof)
        return alpha, beta, commitment, challenge, response

    def make_fingerprint(self, ciphertext_proof):
        """
        Makes fingerprint out of a dictionary of the form

        {'ciphertext': dict, 'proof': dict}

        :type ciphertext_proof: dict
        :rtype: bytes
        """
        fingerprint_params = self.get_fingerprint_params(ciphertext_proof)
        fingerprint = hash_texts(*[str(param) for param in fingerprint_params])
        return fingerprint


    # Mixing and ballots decryption

    def initialize_mixnet(self, module, config, election_key):
        """
        :type module: str
        :type config: dict
        :type election_key: dict
        """
        _cls = self._get_mixnet_class(module)
        return _cls(config, election_key)

    def _get_mixnet_class(self, module):
        """
        :type module: str
        :rtype:
        """
        _module = import_module('mixnets.%s' % module)
        _cls = getattr(_module, module.capitalize())
        return _cls


    #############################################################
    #                                                           #
    #   By factor is meant a dictionary of the form             #
    #                                                           #
    #   {                                                       #
    #     'data': ModPrimElement,                               #
    #     'proof': dict                                         #
    #   }                                                       #
    #                                                           #
    #   where the value of 'proof' is usually a Schnorr-proof   #
    #                                                           #
    #############################################################

    def _set_factor(self, data, proof):
        """
        :type data: ModPrimeElement
        :type proof: dict
        :rtype: dict
        """
        factor = {'data': data, 'proof': proof}
        return factor


    def _extract_factor(self, factor):
        """
        :type factor: dict
        :rtype: (ModPrimeElement, dict)
        """
        return factor['data'], factor['proof']


    ###########################################################
    #                                                         #
    #   By trustee-factors is meanta dictionary of the form   #
    #                                                         #
    #   {                                                     #
    #       'public': ModPrimeElement,                        #
    #       'factors': list[factor]                           #
    #   }                                                     #
    #                                                         #
    #   where the value of 'public' is thought of as the      #
    #   trustee's public key                                  #
    #                                                         #
    ###########################################################

    def _set_trustee_factors(self, public, factors):
        """
        :type public:
        :type factors: list[dict]
        :rtype: dict
        """
        trustee_factors = {'public': public, 'factors': factors}
        return trustee_factors

    def _extract_trustee_factors(self, trustee_factors):
        """
        :type trustee_factors: dict
        :rtype: tuple
        """
        public = trustee_factors['public']
        factors = trustee_factors['factors']
        return public, factors


    def compute_zeus_factors(self, mixed_ballots, secret):
        """
        :type mixed_ballots: list
        :type secret: str
        """
        secret = mpz(secret)
        return self._compute_decryption_factors(secret, mixed_ballots)

    def compute_trustee_factors(self, mixed_ballots, trustee_keypair):
        """
        Trustee keypair: {
            private: mpz,
            public: {
                'value': ModPrimeElement,
                ['proof': dict]
            }
        }

        Mixed ballots: list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}]

        Returns: {'public': ModPrimeElement, 'factors': list[dict]}

        :type trustee_kaypair: dict
        :type mixed_ballots: list[dict]
        :rtype: dict
        """
        trustee_secret, trustee_public = self.extract_keypair(trustee_keypair)
        factors = self._compute_decryption_factors(trustee_secret, mixed_ballots)
        trustee_factors = self._set_trustee_factors(trustee_public, factors)
        return trustee_factors

    # def validate_trustee_factors(self, mixed_ballots, trustee_factors):
    def validate_trustee_factors(self, trustee_public, mixed_ballots, trustee_factors):
        """
        Verifies each one of the `trustee_factors` as the decryption factor of
        the corresponding cipher from `mixed` ballots under the provided public
        `trustee_public` (cf. the ._verify_decryption_factors() method)

        Returns `True` if all factors are successfully validated, otherwise
        an `InvalidFactorError` is raised

        :type trustee_public: dict
        :type mixed_ballots: list
        :type trustee_factors: list[dict]
        :rtype: bool
        """
        # trustee_public, decryption_factors = self._extract_trustee_factors(trustee_factors)
        _, decryption_factors = self._extract_trustee_factors(trustee_factors)

        # Delete this snipset in alterative version
        if not trustee_public or not trustee_factors:
            err = 'Malformed trustee factors'
            raise InvalidFactorError(err)

        trustee_public = self.get_value(trustee_public)

        if not self._verify_decryption_factors(trustee_public, mixed_ballots, decryption_factors):
            err = 'Invalid trustee factors'
            raise InvalidFactorError(err)

        return True

    def decrypt_ballots(self, mixed_ballots, trustees_factors, zeus_factors):
        """
        Mixed ballots: list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}]

        Trustees factors: list[{'public': ModPrimeElement, 'factors': list[{'data': ModPrimeElement, 'proof': ...}]}]

        Zeus factors: list[{'data': ModPrimeElement, 'proof': ...}]

        :type mixed_ballots: list[list]
        :type trustees_factors: list[list[dict]]
        :type zeus_factors: list[dict]
        :rtype:
        """
        plaintexts = []
        append = plaintexts.append

        all_factors = [trustee_factors['factors'] for trustee_factors in trustees_factors]
        all_factors.append(zeus_factors)

        decryption_factors = self._combine_decryption_factors(all_factors)
        for ballot, factor in zip(mixed_ballots, decryption_factors):
            # decryption_factors:
            #          |ballot_1   |ballot_2   |ballot_3   |.........
            # ---------|-----------------------------------|---------
            #     zeus |factor01   |factor02   |factor03   |.........
            # trustee1 |factor11   |factor12   |factor13   |.........
            # trustee2 |factor21   |factor22   |factor23   |.........
            # trustee3 |factor31   |factor32   |factor33   |.........
            # ---------|-----------------------------------|---------
            #          |factor_1   |factor_2   |factor_3   |.........
            encoded = self._decrypt_with_decryptor(ballot, factor)
            append(encoded.to_integer())

        return plaintexts

    def validate_ballots_decryption(self, mixed_ballots, trustees_factors,
            public_shares, zeus_factors, zeus_public_key):
        """
        Mixed ballots: list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}]

        Public shares: list[ModPrimeElement] or list[{'public': ModPrimElement, 'proof': ...}]

        Trustees factors: list[{
            'public': ModPrimeElement or {'public': ModPrimeElement, 'proof': ...},
            'factors': list[{'data': ModPrimeElement, 'proof': dict}]
        }]

        Zeus factors: list[{'data': ModPrimeElement, 'proof': dict}]

        :type mixed_ballots: list[dict]
        :type trustees_factors: list[list[dict]]
        :type public_shares: list[ModPrimeElement]
        :type zeus_factors: list[dict]
        :type zeus_public_key: ModPrimeElement
        :rtype: boolean
        """
        # Lengths check
        if len(trustees_factors) is not len(public_shares):
            err = 'Unequal number of public shares and trustees'
            raise BallotDecryptionError(err)

        # Remove proofs from trustees' public keys
        aux_factors = {}
        for trustee_factors in trustees_factors:
            public, factors = self._extract_trustee_factors(trustee_factors)
            public = self.get_value(public)
            aux_factors[public] = factors
        trustees_factors = aux_factors

        # Verify trustees' factors
        for share in public_shares:
            trustee_public = self.get_value(share)
            try:
                trustee_factors = trustees_factors[trustee_public]
            except KeyError:
                err = 'Trustee mismatch with public shares'
                raise BallotDecryptionError(err)

            if not self._verify_decryption_factors(trustee_public, mixed_ballots, trustee_factors):
                err = 'Trustee\'s factors could not be verified'
                raise BallotDecryptionError(err)

        # Verify zeus's factors
        zeus_public_key = self.get_value(zeus_public_key)
        if not self._verify_decryption_factors(zeus_public_key, mixed_ballots, zeus_factors):
            err = 'Zeus\'s factors could not be verified'
            raise BallotDecryptionError(err)

        return True


    def _compute_decryption_factors(self, secret, ciphers):
        """
        Uses the provided `secret` x to construct a presumable DDH tuple for
        each of the provided `ciphers` and generates presumed proof-of-knowledge
        that the constructed tuple is DDH

        Returns a list of these proofs along with the last member of the
        corresponding DDH

        For each ciphertext

        {'alpha': a, 'beta': ...}

        from the provided `ciphers`, provided that

        a = g ^ r (modp)

        as the result of ElGamal-encryption, generate a proof-of-knowledge
        (Chaum-Pedersen) s that the tuple

                g ^ r (modp), g ^ x (modp), g ^ (r * x) modp

        is DDH and return the list of pairs

        {'data': g ^ (r * x) (modp), 'proof': s}

        :type secret: mpz
        :type ciphers: list[dict]
        :rtype: list[dict]
        """
        public = self.group.generate(secret)                        # g ^ x         (mod p)

        factors = []
        append = factors.append
        for cipher in ciphers:

            alpha, _ = self.extract_ciphertext(cipher)             # g ^ r         (mod p)
            data = alpha ** secret                                  # g ^ (x * r)   (mod p)

            ddh = (alpha, public, data)

            proof = self._chaum_pedersen_proof(ddh, secret)
            factor = self._set_factor(data, proof)
            append(factor)

        return factors

    def _verify_decryption_factors(self, public, ciphers, factors):
        """
        Returns `True` iff all the provided cipher-factor pairs are
        successfully verified under the provided `public` y

        .. note:: `False` is returned if the number of ciphers is unequal
        to the number of factors

        For each ciphertext

        {'alpha': a, 'beta': ...}

        from the provided `ciphers` and corresponding factor

        {'data': c, 'proof': s}

        from the provided `factors`, the current cipher-factor pair will be
        verified iff the (Shnorr-proof) s proves knowledge that the tuple

        (a, y, c)

        is a DDH

        :type public: ModPrimeElement
        :type ciphers: list[dict]
        :type factors: list[dict]
        :rtype: bool
        """
        if len(ciphers) != len(factors):
            return False

        for cipher, factor in zip(ciphers, factors):
            alpha, _ = self.extract_ciphertext(cipher)
            data, proof = self._extract_factor(factor)

            ddh = (alpha, public, data)
            if not self._chaum_pedersen_verify(ddh, proof):
                return False

        return True

    def _combine_decryption_factors(self, trustees_factors):
        """
        Componentwise multiplication

        Given a 2D structure

        [[f_11, ..., f_1n], ..., [f_m1, ... f_mn]]

        of group elements, computes and returns the list

        [f_11 * ... * f_m1, ..., f_1n * ... * f_mn]

        .. note:: Returns a non-sensical 0 if the provided collection comprises
        of empty lists (including the case that the collection itself is empty)

        :type trustees_factors: list[list[{'data': ModPrimeElement, 'proof': ...}]]
        :rtype: list[ModPrimeElement]
        """
        if not trustees_factors or trustees_factors == [[]] * len(trustees_factors):
            return 0

        master_factors = []
        append = master_factors.append

        for factors_column in zip(*trustees_factors):
            master_factor = self.__group.unit
            for trustee_factor in factors_column:
                data, _ = self._extract_factor(trustee_factor)
                master_factor *= data
            append(master_factor)

        return master_factors


    # def convert_mixes_to_elements(self, mixes):
    #     """
    #     :type mixes:
    #     :rtype:
    #     """
    #     for mix in mixes:
    #         # mix_keys = mix.keys()
    #         # if 'mixed_ciphers' in mix_keys:
    #         #     mix['mixed_ciphers'] = [{
    #         #         'alpha': cipher['alpha'],
    #         #         'beta': cipher['beta']
    #         #     } for cipher in mix['mixed_ciphers']]
    #         # elif 'original_ciphers' in mix_keys:
    #         #     mix['original_ciphers'] = [{
    #         #         'alpha': cipher['alpha'],
    #         #         'beta': cipher['beta']
    #         #     } for cipher in mix['original_ciphers']]
    #         key = 'mixed_ciphers' if 'mixed_ciphers' in mix.keys() else 'original_ciphers'
    #         try:
    #             mix[key] = [{'alpha': cipher['alpha'], 'beta': cipher['beta']}
    #                 for cipher in mix[key]]
    #         except KeyError:
    #             continue
    #     return mixes
    #
    #
    # def convert_mixes(self, mixes):
    #     """
    #     :type mixes:
    #     :rtype:
    #     """
    #     for mix in mixes:
    #         # mix_keys = mix.keys()
    #         # if 'mixed_ciphers' in mix_keys:
    #         #     mix['mixed_ciphers'] = [{
    #         #         'alpha': cipher['alpha'].value,
    #         #         'beta': cipher['beta'].value
    #         #     } for cipher in mix['mixed_ciphers']]
    #         # elif 'original_ciphers' in mix_keys:
    #         #     mix['original_ciphers'] = [{
    #         #         'alpha': cipher['alpha'].value,
    #         #         'beta': cipher['beta'].value
    #         #     } for cipher in mix['original_ciphers']]
    #         key = 'mixed_ciphers' if 'mixed_ciphers' in mix.keys() else 'original_ciphers'
    #         try:
    #             mix[key] = [{
    #                 'alpha': cipher['alpha'].value,
    #                 'beta': cipher['beta'].value
    #             } for cipher in mix[key]]
    #         except KeyError:
    #             continue
    #     return mixes
    #
    #
    # def _get_last_mix(mixes):
    #     """
    #     """
    #     return mixes[-1]
