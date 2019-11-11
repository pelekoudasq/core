"""
Sako-Killian mixnet
"""

from Crypto import Random
from itertools import chain
from hashlib import sha256

from ..exceptions import MixNotVerifiedError, RoundNotVerifiedError

ALPHA = 0
BETA  = 1

from zeus_core.crypto.modprime import ModPrimeCrypto
from zeus_core.utils import random_permutation, AsyncController, _teller, bit_iterator

from ..abstracts import Mixnet
from ..exceptions import MixnetError, MixNotVerifiedError, RoundNotVerifiedError


class Zeus_sk(Mixnet):
    """
    Implementation of Sako-Killian mixnet
    """

    supported_crypto = (ModPrimeCrypto,)

    def __init__(self, config, election_key=None):
        """
        Provided `config` should be a structure of the form

        {
            'cryptosys': ElGamalCrypto,
            'nr_rounds': int,
            'nr_mixes': int
        }

        where the class of 'cryptosys' should be contained in `supported_crypto`,
        'nr_rounds' is the number of rounds to be performed during mixing and
        'nr_mixes' is the fixed length of cipher-collections to mix.

        ..raises MixnetError:: if the provided config is not as prescribed
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

        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_mixes
        self.substract = self.__class__.mk_substract_func(
            order=cryptosys.parameters()['order'])

    @classmethod
    def mk_substract_func(cls, order):
        def substract(a, b):
            return (a - b) % order
        return substract

    def get_config(self):
        config = {}
        config['cryptosys'] = self.cryptosys
        config['nr_rounds'] = self.__nr_rounds
        config['nr_mixes'] = self.__nr_mixes
        return config


    # Mixing

    def mix_ciphers(self, original_mix, nr_parallel=None, nr_rounds=None, teller=_teller):
        """
        Structure of the produced cipher-mix is

        {
            'header': {
                ...
                'public': GroupElement
            },
            'original_ciphers': list[(GroupElement, GroupElement)]
            'mixed_ciphers': list[(GroupElement, GroupElement)]
            'proof': {
                'cipher_collections': ...,
                'offset_collections': ...,
                'random_collections': ...,
                'challenge': str
            }
        }
        """
        cipher_mix = {}
        cipher_mix['header'] = self.header
        original_ciphers = original_mix['mixed_ciphers']
        cipher_mix['original_ciphers'] = original_ciphers
        cipher_mix['proof'] = {}

        nr_rounds = self.__nr_rounds
        if nr_parallel is None:
            nr_parallel = 0
        election_key = self.election_key
        nr_ciphers = len(original_ciphers)
        proof = cipher_mix['proof']

        # Proceed to mixing

        teller.task('Mixing %d ciphers for %d rounds' % (nr_ciphers, nr_rounds))

        encrypt_func = self._reencrypt
        with teller.task('Producing final mixed ciphers'):
            mixed_ciphers, mixed_offsets, mixed_randoms = self.shuffle_ciphers(
                original_ciphers, election_key, encrypt_func, teller=teller)
            cipher_mix['mixed_ciphers'] = mixed_ciphers

        total = nr_ciphers * nr_rounds
        with teller.task('Producing ciphers for proof', total=total):
            _async = None
            if nr_parallel > 0:
                Random.atfork()
                _async = AsyncController(parallel=nr_parallel)
                async_shuffle_ciphers = _async.make_async(shuffle_ciphers)

            if _async:
                channels = [async_shuffle_ciphers(original_ciphers, election_key, encrypt_func,
                                teller=teller) for _ in range(nr_rounds)]
                count = 0
                while count < total:
                    nr = _async.receive_shared()
                    teller.advance(nr)
                    count += nr

                collections = [channel.receive(wait=1) for channel in channels]
                _async.shutdown()
            else:
                shuffle_ciphers = self.shuffle_ciphers
                collections = [shuffle_ciphers(original_ciphers,
                    election_key, encrypt_func, teller=teller) for _ in range(nr_rounds)]

            unzipped = [list(x) for x in zip(*collections)]
            cipher_collections, offset_collections, random_collections = unzipped
            proof['cipher_collections'] = cipher_collections
            proof['offset_collections'] = offset_collections
            proof['random_collections'] = random_collections

        # Produce challenge
        with teller.task('Producing cryptographic hash challenge'):
            # challenge = compute_mix_challenge(cipher_mix)
            challenge = self.compute_mix_challenge(cipher_mix)
            proof['challenge'] = challenge

        # Modify collections according to challenge
        bits = bit_iterator(int(challenge, 16))
        substract = self.substract
        with teller.task('Making collections according to challenge', total=nr_rounds):
            for i, bit in zip(range(nr_rounds), bits):
                ciphers = cipher_collections[i]
                offsets = offset_collections[i]
                randoms = random_collections[i]
                if bit == 0:
                    pass
                elif bit == 1:
                    new_offsets = [None] * nr_ciphers
                    new_randoms = [None] * nr_ciphers
                    for j in range(nr_ciphers):
                        k = offsets[j]
                        new_offsets[k] = mixed_offsets[j]
                        new_randoms[k] = self.substract(mixed_randoms[j], randoms[j])
                    offset_collections[i] = new_offsets
                    random_collections[i] = new_randoms
                    del offsets, randoms
                else:
                    err = 'This should be impossible. Something is broken'
                    raise AssertionError(err)
                teller.advance()
        teller.finish('Mixing')
        return cipher_mix


    def shuffle_ciphers(self, ciphers, election_key, encrypt_func, teller=None,
                report_thres=128, async_channel=None):
        """
        Reencrypts the provided `ciphers` under the given key `election_key` and returns a random
        permutation of the new ciphers, along with the list of indices encoding this
        permutation and the randomnesses used for re-encryption in the original order

        :type ciphers: list[(ModPrimeElement, ModPrimeElement)]
        :type election_key: ModPrimeElement
        :type encrypt_func:
        :rtype: (list[(ModPrimeElement, ModPrimeElement)], list[int], list[mpz])
        """
        nr_ciphers = len(ciphers)
        mixed_offsets = random_permutation(nr_ciphers)

        mixed_ciphers = [None] * nr_ciphers
        mixed_randoms = [None] * nr_ciphers
        count = 0
        _reencrypt = self._reencrypt
        for i in range(nr_ciphers):

            alpha, beta = ciphers[i]
            alpha, beta, secret = _reencrypt(alpha, beta, election_key, get_secret=True)

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


    def compute_mix_challenge(self, cipher_mix):
        """
        """
        hasher = sha256()
        update = hasher.update

        update(''.join(cipher_mix['header'].values()).encode('utf-8'))

        original_ciphers = cipher_mix['original_ciphers']
        mixed_ciphers = cipher_mix['mixed_ciphers']
        cipher_collections = cipher_mix['proof']['cipher_collections']

        ciphers = chain(original_ciphers, mixed_ciphers, *cipher_collections)
        for cipher in ciphers:
            update((cipher[ALPHA].to_hex()).encode('utf-8'))
            update((cipher[BETA].to_hex()).encode('utf-8'))

        challenge = hasher.hexdigest()
        return challenge


    # Testing

    def verify_mix(self, cipher_mix, nr_parallel=0, min_rounds=None, teller=_teller):
        """
        """
        _, election_key = self.extract_header(cipher_mix)
        original_ciphers = cipher_mix['original_ciphers']
        mixed_ciphers = cipher_mix['mixed_ciphers']
        proof = cipher_mix['proof']
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
        if challenge != self.compute_mix_challenge(cipher_mix):
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
            verify_mix_round = self.verify_mix_round
            for i, bit in zip(range(nr_rounds), bit_iterator(int(challenge, 16))):
                ciphers = cipher_collections[i]
                offsets = offset_collections[i]
                randoms = random_collections[i]

                if _async:
                    append(async_verify_mix_round(i, bit,
                                    original_ciphers, mixed_ciphers, ciphers,
                                    offsets, randoms, encrypt_func,
                                    election_key, teller=None))
                else:
                    try:
                        verify_mix_round(i, bit, original_ciphers, mixed_ciphers,
                                        ciphers, offsets, randoms, encrypt_func,
                                        election_key, teller=None)
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

    def verify_mix_round(self, round_nr, bit, original_ciphers, mixed_ciphers,
            ciphers, offsets, randoms, encrypt_func, election_key,
            teller=None, report_thres=128, async_channel=None):
        """
        Returns True if the round is successfully verified,
        otherwise raises `RoundNotVerifiedError`
        """
        nr_ciphers = len(original_ciphers)

        if bit == 0:
            preimages = original_ciphers
            images = ciphers
        elif bit == 1:
            preimages = ciphers
            images = mixed_ciphers
        else:
            err = 'This should be impossible. Something is broken'
            raise AssertionError(err)

        count = 0
        _reencrypt = self._reencrypt
        for j in range(nr_ciphers):
            preimage = preimages[j]
            random = randoms[j]
            offset = offsets[j]

            alpha = preimage[ALPHA]
            beta = preimage[BETA]
            new_alpha, new_beta = _reencrypt(alpha, beta, election_key, randomness=random)

            image = images[offset]
            if new_alpha != image[ALPHA] or new_beta != image[BETA]:
                err = 'MIXING VERIFICATION FAILED AT ROUND %d CIPHER %d bit %d' % (
                        round_nr, j, bit)
                raise RoundNotVerifiedError(err)

            count += 1
            if count >= report_thres:
                if async_channel:
                    async_channel.send_shared(count)
                if teller:
                    teller.advance(count)
                count = 0

        if count:
            if async_channel:
                async_channel.send_shared(count)
            if teller:
                teller.advance(count)

        return True
