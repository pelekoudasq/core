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

        # Set crypto parameters

        self.__cryptosystem = cryptosystem
        self.__group = self.__cryptosystem.group

        parameters = cryptosystem.parameters
        self.__modulus = parameters['modulus']
        self.__order = parameters['order']
        self.__generator = parameters['generator']

        # Set mixing parameters

        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_mixes

        # Set election key

        self.__election_key = self.__cryptosystem._extract_value(election_key)

    @classmethod
    def supports_cryptosystem(cls, cryptosystem):
        """
        :type cryptosystem:
        :rtype: bool
        """
        return cryptosystem.__class__ in cls.supported_crypto

    @property
    def cryptosystem(self):
        """
        Returns the mixnet's fixed cryptosystem

        :rtype: ModPrimeCrypto
        """
        return self.__cryptosystem


    # Encryption

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


    # Formats

    def _prepare_mix(self, cipher_collection):
        """
        Assuming `cipher_collection` to be a dictionary of the form

        {
            'original_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],
            ['mixed_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],]
            ['proof': ...]
            ...
        }

        returns a dictionary of the form

        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement,
            'original_ciphers': list[(ModPrimeElement, ModPrimeElement)],
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)],
            ['proof': ...]
        }

        where 'modulus', 'order', 'generator' are the parameters of the mixnet's
        cryptosystem, 'public' is the mixnet's fixed election key and 'proof' is
        directly extracted form the provided collection' (if provided)

        If `mixed_ciphers` is not provided by the given collection, then the
        corresponding value in the output will be the value of `original_ciphers`


        :type cipher_collection: dict
        :rtype: dict
        """
        res = {}

        res['modulus'] = self.__modulus
        res['order'] = self.__order
        res['generator'] = self.__generator
        res['public'] = self.__election_key

        if 'original_ciphers' in cipher_collection:
            res['original_ciphers'] = \
                [(c['alpha'], c['beta']) for c in cipher_collection['original_ciphers']]

        if 'mixed_ciphers' in cipher_collection:
            res['mixed_ciphers'] = \
                [(c['alpha'], c['beta']) for c in cipher_collection['mixed_ciphers']]
        elif 'original_ciphers' in cipher_collection:
            res['mixed_ciphers'] = res['original_ciphers']

        if 'proof' in cipher_collection:
            res['proof'] = cipher_collection['proof']

        return res

    def _extract_mix(self, mixed_collection):
        """
        Assuming `mixed_collection` to be a dictionary of the form

        {
            'original_ciphers': list[(ModPrimeElement, ModPrimeElement)],
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)],
            'proof': ...,
            ...
        }

        returns a dictionary of the form

        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement,
            'original_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}]
            'mixed_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],
            'proof': ...
        }

        where 'modulus', 'order', 'generator' are the parameters of the mixnet's
        cryptosystem, 'public' is the mixnet's fixed election key and 'proof' is
        directly extracted form the provided collection

        :type mixed_collection: dict
        :rtype: dict
        """
        res = {}

        res['modulus'] = self.__modulus
        res['order'] = self.__order
        res['generator'] = self.__generator
        res['public'] = self.__election_key

        for KEY in ('original_ciphers', 'mixed_ciphers',):
            res[KEY] = [{'alpha': c[0], 'beta': c[1]} for c in mixed_collection[KEY]]

        res['proof'] = mixed_collection['proof']

        return res



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
