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
        self.__reencrypt = cryptosystem.reencrypt

        self.__nr_rounds = nr_rounds
        self.__nr_mixes = nr_rounds

        self.__election_key = cryptosystem._extract_value(election_key)

    @classmethod
    def supports_cryptosystem(cls, cryptosystem):
        """
        """
        return cryptosystem.__class__ in cls.supported_crypto

    @property
    def election_key(self):
        return self.__election_key

    def reencrypt(self, ciphertext, public_key, randomness):
        return self.__cryptosystem.reencrypt(ciphertext, public_key, randomness)
