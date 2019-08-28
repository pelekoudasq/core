from gmpy2 import mpz

from ..abstracts import Mixnet, MixnetError
from crypto import ModPrimeCrypto, ModPrimeElement, WrongCryptoError
from utils import random_permutation
from utils.async import AsyncController
from utils.teller import _teller
from utils.binutils import bit_iterator
from .utils import (shuffle_ciphers, compute_mix_challenge,
    RoundNotVerifiedError, verify_mix_round)

MIN_MIX_ROUNDS = 1

class MixNotVerifiedError(BaseException):
    """
    Raised when a cipher-mix fails to be verified
    """
    pass


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

        for key in ('original_ciphers', 'mixed_ciphers',):
            res[key] = [{'alpha': c[0], 'beta': c[1]} for c in mixed_collection[key]]

        res['proof'] = mixed_collection['proof']

        return res


    # Core

    def mix_ciphers(self, ciphers_to_mix, nr_rounds=MIN_MIX_ROUNDS,
            teller=_teller, nr_parallel=0):
        """
        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement
            'original_ciphers': ...
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            ...
        }

        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement,
            'original_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            'proof': {
                'cipher_collections':,
                'offset_collections':,
                'random_collections':
                'challenge': str
            }
        }

        :type ciphers_to_mix: dict
        :rtype: dict
        """
        cipher_mix = {}
        order = self.__order
        public = self.__election_key
        original_ciphers = ciphers_to_mix['mixed_ciphers']

        # Set some data

        cipher_mix['modulus'] = self.__modulus
        cipher_mix['order'] = order
        cipher_mix['generator'] = self.__generator
        cipher_mix['public'] = public
        cipher_mix['original_ciphers'] = original_ciphers
        cipher_mix['proof'] = {}

        proof = cipher_mix['proof']
        nr_ciphers = len(original_ciphers)

        # Proceed to mixing

        teller.task('Mixing %d ciphers for %d rounds' % (nr_ciphers, nr_rounds))

        encrypt_func = self._reencrypt
        with teller.task('Producing final mixed ciphers'):
            mixed_ciphers, mixed_offsets, mixed_randoms = shuffle_ciphers(
                original_ciphers, public, encrypt_func, teller=teller)
            cipher_mix['mixed_ciphers'] = mixed_ciphers

        total = nr_ciphers * nr_rounds
        with teller.task('Producing ciphers for proof', total=total):
            _async = None
            if nr_parallel > 0:
                Random.atfork()
                _async = AsyncController(parallel=nr_parallel)
                async_shuffle_ciphers = _async.make_async(shuffle_ciphers)

            if _async:
                channels = [async_shuffle_ciphers(original_ciphers, public, encrypt_func,
                                teller=teller) for _ in range(nr_rounds)]
                count = 0
                while count < total:
                    nr = _async.receive_shared()
                    teller.advance(nr)
                    count += nr

                collections = [channel.receive(wait=1) for channel in channels]
                _async.shutdown()
            else:
                collections = [shuffle_ciphers(original_ciphers, public, encrypt_func, teller=teller)
                    for _ in range(nr_rounds)]

            unzipped = [list(x) for x in zip(*collections)]
            cipher_collections, offset_collections, random_collections = unzipped
            proof['cipher_collections'] = cipher_collections
            proof['offset_collections'] = offset_collections
            proof['random_collections'] = random_collections

        # Produce challenge
        with teller.task('Producing cryptographic hash challenge'):
            challenge = compute_mix_challenge(cipher_mix)
            proof['challenge'] = challenge

        # Modify collections according to challenge
        bits = bit_iterator(int(challenge, 16))
        with teller.task('Making collections according to challenge', total=nr_rounds):
            for i, bit in zip(range(nr_rounds), bits):
                ciphers = cipher_collections[i]
                offsets = offset_collections[i]
                randoms = random_collections[i]

                if bit == 0:
                    pass              # Do nothing, just publish offsets and randoms
                elif bit == 1:
                    new_offsets = [None] * nr_ciphers
                    new_randoms = [None] * nr_ciphers

                    for j in range(nr_ciphers):
                        k = offsets[j]
                        new_offsets[k] = mixed_offsets[j]
                        new_randoms[k] = (mixed_randoms[j] - randoms[j]) % order

                    offset_collections[i] = new_offsets
                    random_collections[i] = new_randoms

                    del offsets, randoms
                else:
                    e = 'This should be impossible. Something is broken'
                    raise AssertionError(e)
                teller.advance()

        teller.finish('Mixing')
        return cipher_mix


    def verify_cipher_mix(self, cipher_mix, teller=_teller, min_rounds=None, nr_parallel=0):
        """
        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement,
            'original_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            'proof': {
                'cipher_collections':,
                'offset_collections':,
                'random_collections':
                'challenge': str
            }
        }

        :type cipher_mix: dict
        :type teller:
        :type min_rounds: int
        :type nr_parallel: int
        """
        try:
            modulus = cipher_mix['modulus']
            order = cipher_mix['order']
            generator = cipher_mix['generator']
            public = cipher_mix['public']
            original_ciphers = cipher_mix['original_ciphers']
            mixed_ciphers = cipher_mix['mixed_ciphers']
            proof = cipher_mix['proof']
        except KeyError as error:
            e = 'Invalid mix format: \'%s\' missing' % error.args[0]
            raise MixNotVerifiedError(e)

        try:
            cipher_collections = proof['cipher_collections']
            offset_collections = proof['offset_collections']
            random_collections = proof['random_collections']
            challenge = proof['challenge']
        except KeyError as error:
            e = 'Malformed proof provided: \'%s\' missing' % error.args[0]
            raise MixNotVerifiedError(e)

        nr_ciphers = len(original_ciphers)
        nr_rounds = len(cipher_collections)

        # Validate challenge
        if challenge != compute_mix_challenge(cipher_mix):
            e = 'Invalid challenge'
            raise MixNotVerifiedError(e)

        teller.task('Verifying mixing of %d ciphers for %d rounds'
            % (nr_ciphers, nr_rounds))

        # Check rounds lower boundary
        if min_rounds is not None and nr_rounds < min_rounds:
            e = 'Invalid mix: rounds fewer than required: %d < %d' % (
                    nr_rounds, min_rounds)
            raise MixNotVerifiedError(e)

        # Check collections lengths
        if (len(offset_collections) != nr_rounds or
            len(random_collections) != nr_rounds):
            e = 'Invalid mix format: collections not of the same size'
            raise MixNotVerifiedError(e)

        # Verify mix rounds
        total = nr_rounds * nr_ciphers
        with teller.task('Verifying ciphers', total=total):
            _async = None
            if nr_parallel > 0:
                _async = AsyncController(parallel=nr_parallel)
                channels = []
                append = channels.append
                async_verify_mix_round = _async.make_async(verify_mix_round)

            encrypt_func = self._reencrypt
            for i, bit in zip(range(nr_rounds), bit_iterator(int(challenge, 16))):
                ciphers = cipher_collections[i]
                offsets = offset_collections[i]
                randoms = random_collections[i]

                if _async:
                    append(async_verify_mix_round(i, bit,
                                    original_ciphers, mixed_ciphers, ciphers,
                                    offsets, randoms, encrypt_func,
                                    public, teller=None))
                else:
                    try:
                        verify_mix_round(i, bit, original_ciphers, mixed_ciphers,
                                        ciphers, offsets, randoms, encrypt_func,
                                        public, teller=None)
                    except RoundNotVerifiedError as error:
                        e = error.args[0]
                        raise MixNotVerifiedError(e)

            # TODO: Refine try/except?
            if _async:
                try:
                    count = 0
                    while count < total:
                        nr = _async.receive_shared(wait=1)
                        teller.advance(nr)
                        count += 1

                    for channel in channels:
                        channel.receive(wait=1)
                except RoundNotVerifiedError as error:
                    e = error.args[0]
                    raise MixNotVerifiedError(e)

                _async.shutdown()

        teller.finish('Verifying mixing')
        return True
