from gmpy2 import mpz

from ..abstracts import Mixnet, MixnetError
from crypto import ModPrimeCrypto, ModPrimeElement, WrongCryptoError
from utils import random_permutation


class Zeus_SK(Mixnet):
    """
    """

    supported_crypto = (ModPrimeCrypto,)

    __slots__ = ('__cryptosystem', '__group', '__nr_rounds', '__nr_mixes', '__election_key')

    def __init__(self, config, election_key):
        """
        :type config: dict
        :type election_key: dict
        """
        try:
            cryptosystem = config['cryptosystem']
            nr_rounds = config['nr_rounds']
            nr_mixes = config['nr_mixes']
        except KeyError:
            e = 'Malformed parameters for Zeus SK mixnet'
            raise MixnetError(e)

        if not self.supports_cryptosystem(cryptosystem):
            e = 'Provided crypto type is not supported by Zeus SK mixnet'
            raise WrongCryptoError(e)

        self.__cryptosystem = cryptosystem
        self.__group = self.__cryptosystem.group

        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_rounds

        self.__election_key = self.__cryptosystem._extract_value(election_key)

    @classmethod
    def supports_cryptosystem(cls, cryptosystem):
        """
        :type cryptosystem:
        :rtype: bool
        """
        return cryptosystem.__class__ in cls.supported_crypto


    def _reencrypt(self, alpha, beta, public, randomness=None, get_secret=False):
        """
        This is a slighlty modified version of the `ModPrimeCrypto.reencrypt()`
        method adapted to the context of mixnet input/output (so that no
        unnecessary extractions need take place)

        See doc of that function for insight

        :type alpha: ModPrimeElement
        :type beta: ModPrimeElement
        :type public: ModPrimeElement
        :randomness: mpz
        :get_secret: bool
        :rtype: (ModPrimeElement, ModPrimeElement[, mpz])
        """
        __group = self.__group

        if randomness is None:
            randomness = __group.random_exponent(min=3)

        alpha = alpha * __group.generate(randomness)                # a * g ^ r
        beta = beta * public ** randomness                          # b * y ^ r

        if get_secret:
            return alpha, beta, randomness
        return alpha, beta


    def _shuffle_ciphers(self, ciphers, public,
                teller=None, report_thres=128, async_channel=None):
        """
        Reencrypts the provided `ciphers` under the given key `public` and
        returns a random permutation of the new ciphers, along with the
        list of indices encoding this permutation and the randomnesses
        used for re-encryption in the original order

        :type ciphers: list[(ModPrimeElement, ModPrimeElement)]
        :rtype: (list(ModPrimeElement, ModPrimeElement), list[int], list[mpz])
        """
        nr_ciphers = len(ciphers)
        mixed_offsets = random_permutation(nr_ciphers)

        mixed_ciphers = [None] * nr_ciphers
        mixed_randoms = [None] * nr_ciphers
        count = 0
        for i in range(nr_ciphers):

            alpha, beta = ciphers[i]
            alpha, beta, secret = self._reencrypt(alpha, beta, public, get_secret=True)

            mixed_randoms[i] = secret
            j = mixed_offsets[i]
            mixed_ciphers[j] = (alpha, beta)

            count += 1
            if teller:
                teller.advance(count)
            if async_channel:
                async_channel.send_shared(count, wait=1)
            if count >= report_thres:
                count = 0

        return mixed_ciphers, mixed_offsets, mixed_randoms


    # def prepare_mix(self, cipher_collection):
    #     """
    #     :type cipher_collection:
    #     :rtype:
    #     """
    #     pass
    #
    # def extract_mix(self, mixed_collection):
    #     """
    #     Assumes a dictionary of the form
    #
    #     {
    #         'mixed_ciphers': list[tuple],
    #         'original_ciphers': list[tuple],
    #         'proof': ...
    #     }
    #
    #     :type mixed_collection: dict
    #     :rtype: dict
    #     """
    #     system = self.__cryptosystem
    #
    #     mixed_ciphers = [self.__cryptosystem._set_ciphertext(alpha, beta)
    #         for (alpha, beta) in mixed_collection['mixed_ciphers']]
    #
    #     original_ciphers = [self.__cryptosystem._set_ciphertext(alpha, beta)
    #         for (alpha, beta) in mixed_collection['original_ciphers']]
    #
    #     proof = mixed_collection['proof']
    #
    #     modulus, order, generator = system.parameters()
    #
    #     mix = {}
    #
    #     mix['modulus'] = modulus,
    #     mix['order'] = order,
    #     mix['generator'] = generator,
    #     mix['public'] = self.__election_key,
    #     mix['mixed_ciphers'] = mixed_ciphers,
    #     mix['original_ciphers'] = original_ciphers,
    #     mix['proof'] = proof
    #
    #     return mix
