from ..abstracts import Mixnet, MixnetError
from crypto import ModPrimeCrypto, WrongCryptoError


class Zeus_SK(Mixnet):
    """
    """

    supported_crypto = (ModPrimeCrypto,)

    __slots__ = ('__cryptosystem', '__reencrypt', '__nr_rounds', '__nr_mixes', '__election_key')

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
            e = 'Provided crypto type is not supported by Zeus SK'
            raise WrongCryptoError(e)

        self.__cryptosystem = cryptosystem

        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_rounds

        self.__election_key = self.__cryptosystem._extract_value(election_key)

    @classmethod
    def supports_cryptosystem(cls, cryptosystem):
        """
        """
        return cryptosystem.__class__ in cls.supported_crypto

def reencrypt(self, ciphertext, public_key, randomness):
    return self.__cryptosystem.reencrypt(ciphertext, public_key, randomness)


    def prepare_mix(self, cipher_collection):
        """
        :type cipher_collection:
        :rtype:
        """
        pass


    def extract_mix(self, mixed_collection):
        """
        Assumes a dictionary of the form

        {
            'mixed_ciphers': list[tuple],
            'original_ciphers': list[tuple],
            'proof': ...
        }

        :type mixed_collection: dict
        :rtype: dict
        """
        system = self.__cryptosystem

        mixed_ciphers = [self.__cryptosystem._set_ciphertext(alpha, beta)
            for (alpha, beta) in mixed_collection['mixed_ciphers']]

        original_ciphers = [self.__cryptosystem._set_ciphertext(alpha, beta)
            for (alpha, beta) in mixed_collection['original_ciphers']]

        proof = mixed_collection['proof']

        modulus, order, generator = system.parameters()

        mix = {}

        mix['modulus'] = modulus,
        mix['order'] = order,
        mix['generator'] = generator,
        mix['public'] = self.__election_key,
        mix['mixed_ciphers'] = mixed_ciphers,
        mix['original_ciphers'] = original_ciphers,
        mix['proof'] = proof

        return mix


    def _shuffle_ciphers(ciphers, teller=None, report_thres=128, async_channel=None):
        pass
