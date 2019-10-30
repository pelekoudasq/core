"""
Sako-Killian mixnet
"""

from Crypto import Random
from gmpy2 import mpz

from zeus_core.crypto.modprime import ModPrimeCrypto
from zeus_core.utils import random_permutation, AsyncController, _teller, bit_iterator

from ..abstracts import Mixnet
from ..exceptions import MixnetError, MixNotVerifiedError, RoundNotVerifiedError
from .utils import (shuffle_ciphers, compute_mix_challenge, verify_mix_round)


class Zeus_sk(Mixnet):
    """
    Implementation of Sako-Killian mixnet
    """

    supported_crypto = (ModPrimeCrypto,)

    __slots__ = ('__cryptosys', '__group', '__nr_rounds', '__nr_mixes', '__election_key', '__header',
        '__modulus', '__order', '__generator',)


    def __init__(self, config, election_key=None):
        """
        Provided `config` be a structure of the form

        {'cryptosys': <ElGamalCrypto>, 'nr_rounds': <int>, 'nr_mixes': <int>}

        where
            - the value of `cryptosys` refers to the underlying cryptosystem
              and its class should be contained in `supported_crypto`
            - 'nr_rounds' is the number of rounds to be performed at each mixing
            - 'nr_mixes' is the fixed length of cipher-collections to mix.

        Provided `election_key` should be a structure of the form

        {'value': <GroupElement>, 'proof': None} or <GroupElement>

        thought of as the combined public key of the running election.

        ..raises MixnetError:: if the provided config is not as prescribed

        :type config: dict
        :type election_key: dict
        """
        try:
            cryptosys = config['cryptosys']
            nr_rounds = config['nr_rounds']
            nr_mixes = config['nr_mixes']
        except KeyError:
            err = 'Malformed parameters for Zeus SK mixnet'
            raise MixnetError(err)
        if not self.supports_cryptosys(cryptosys):
            err = 'Provided crypto type is not supported by Zeus SK mixnet'
            raise MixnetError(err)
        super().__init__(cryptosys, election_key)

        parameters = cryptosys.parameters()
        self.__modulus = parameters['modulus']
        self.__order = parameters['order']
        self.__generator = parameters['generator']
        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_mixes


    def get_config(self):
        config = {}
        config['cryptosys'] = self.cryptosys
        config['nr_rounds'] = self.__nr_rounds
        config['nr_mixes'] = self.__nr_mixes
        return config


    # API

    def mix(self, cipher_collection):
        """
        {
            'original_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],
            ['mixed_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],]
            ['proof': ...]
            ...
        }

        :type cipher_collection: dict
        :rtype: dict
        """
        ciphers_to_mix = self._set_cipher_mix(cipher_collection)
        cipher_mix = self.mix_ciphers(ciphers_to_mix)
        return self._extract_cipher_mix(cipher_mix)

    def mix_many(self, prev):
        """
        :type prev: dict
        :rtype: list[dict]
        """
        mixes = []   # mix = [prev]
        appned = mixes.append
        for _ in range(self.__nr_mixes):
            prev = self.mix(prev)
            append(prev)
        return mixes

    def validate(self, cipher_collection):
        """
        {
            'original_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],
            ['mixed_ciphers': list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}],]
            ['proof': ...]
            ...
        }
        :type cipher_collection: dict
        :rtype: bool
        """
        cipher_mix = self._set_cipher_mix(cipher_collection)
        try:
            self.verify_cipher_mix(cipher_mix)
        except MixNotVerifiedError:
            return False # so that it can be used below; otherwise: raise
        return True

    def validate_many(self, cipher_collections):
        """
        :type cipher_collections: list[dict]
        :rtype bool:
        """
        if len(cipher_collections) != self.__nr_mixes:
            err = 'Invalid number of mixes provided'
            raise AssertionError(err)

        validated = True
        validate = self.validate
        for cipher_collection in cipher_collections:
            # TODO: validate if original_ciphers != previous_mixed (?)
            validated = validated and validate(cipher_collection)

        return validated


    # Core

    def mix_ciphers(self, original_mix, teller=_teller, nr_parallel=0):
        """
        Admits:

        {
            'modulus': mpz,
            'order': mpz,
            'generator': mpz,
            'public': ModPrimeElement
            'original_ciphers': ...
            'mixed_ciphers': list[(ModPrimeElement, ModPrimeElement)]
            ...
        }

        Returns:

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

        :type original_mix: dict
        :rtype: dict
        """
        cipher_mix = {}

        nr_rounds = self.__nr_rounds
        order = self.__order
        public = self.election_key
        original_ciphers = original_mix['mixed_ciphers']

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
                collections = [shuffle_ciphers(original_ciphers,
                    public, encrypt_func, teller=teller) for _ in range(nr_rounds)]

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
                    err = 'This should be impossible. Something is broken'
                    raise AssertionError(err)
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
            err = 'Invalid mix format: \'%s\' missing' % error.args[0]
            raise MixNotVerifiedError(err)

        try:
            cipher_collections = proof['cipher_collections']
            offset_collections = proof['offset_collections']
            random_collections = proof['random_collections']
            challenge = proof['challenge']
        except KeyError as error:
            err = 'Malformed proof provided: \'%s\' missing' % error.args[0]
            raise MixNotVerifiedError(err)

        nr_ciphers = len(original_ciphers)
        nr_rounds = len(cipher_collections)

        # Validate challenge
        if challenge != compute_mix_challenge(cipher_mix):
            err = 'Invalid challenge'
            raise MixNotVerifiedError(err)

        teller.task('Verifying mixing of %d ciphers for %d rounds'
            % (nr_ciphers, nr_rounds))

        # Check rounds lower boundary
        if min_rounds is not None and nr_rounds < min_rounds:
            err = 'Invalid mix: rounds fewer than required: %d < %d' % (
                    nr_rounds, min_rounds)
            raise MixNotVerifiedError(err)

        # Check collections lengths
        if (len(offset_collections) != nr_rounds or
            len(random_collections) != nr_rounds):
            err = 'Invalid mix format: collections not of the same size'
            raise MixNotVerifiedError(err)

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
                        err = error.args[0]
                        raise MixNotVerifiedError(err)

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
                    err = error.args[0]
                    raise MixNotVerifiedError(err)

                _async.shutdown()

        teller.finish('Verifying mixing')
        return True
