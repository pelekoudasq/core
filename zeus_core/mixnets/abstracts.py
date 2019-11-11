from abc import ABCMeta, abstractmethod
from copy import deepcopy

from .exceptions import MixNotVerifiedError, InvalidMixError


class Mixnet(object, metaclass=ABCMeta):
    """
    Abstract base class for mixnets
    """

    __slots__ = ('__cryptosys', '__election_key', '__group', '__header')

    def __init__(self, cryptosys, election_key=None):
        self.__cryptosys = cryptosys
        self.__group = cryptosys.group
        header = {}
        header.update(cryptosys.hex_crypto_params())
        if election_key:
            self.__election_key = cryptosys.get_key_value(election_key)
            header.update({'public':
                self.__election_key.to_hex()})
        self.__header = header


    # Initialization

    @classmethod
    def supports_cryptosys(cls, cryptosys):
        return cryptosys.__class__ in cls.supported_crypto

    def set_election_key(self, election_key):
        cryptosys = self.__cryptosys
        self.__election_key = cryptosys.get_key_value(election_key)
        self.__header.update({'public':
            cryptosys.get_key_value(election_key).to_hex()})


    # Properties

    @property
    def cryptosys(self):
        return self.__cryptosys

    @property
    def election_key(self):
        return self.__election_key

    @property
    def group(self):
        return self.__group

    @property
    def header(self):
        return self.__header


    # Mixing

    @abstractmethod
    def mix_ciphers(self, original_mix, nr_parallel=None, **kwargs):
        """
        Admits

        {
            'header': {
                ...
                'public': GroupElement
            },
            'original_ciphers': list[(GroupElement, GroupElement)]
            'mixed_ciphers': list[(GroupElement, GroupElement)]
        }

        where 'original_ciphers' and 'mixed_ciphers' coincide. Returns

        {
            'header': {
                ...
                'public': GroupElement
            },
            'original_ciphers': list[(GroupElement, GroupElement)]
            'mixed_ciphers': list[(GroupElement, GroupElement)]
            'proof': {
                ...
            }
        }

        where structure of 'proof' is mixnet specific
        """

    def _reencrypt(self, alpha, beta, public, randomness=None, get_secret=False):
        """
        This is a slighlty modified version of the `ModPrimeCrypto.reencrypt()`
        method adapted to the context of mixnet input/output (so that no
        unnecessary extractions need take place)

        See doc of that function for insight

        :type alpha: GroupElemement
        :type beta: GroupElemement
        :type public: GroupElemement
        :randomness: exponent
        :get_secret: bool
        :rtype: (GroupElement, GroupElement[, exponent])
        """
        __group = self.__group

        if randomness is None:
            randomness = __group.random_exponent(min=3)

        alpha = alpha * __group.generate(randomness)                # a * g ^ r
        beta = beta * public ** randomness                          # b * y ^ r

        if get_secret:
            return alpha, beta, randomness
        return alpha, beta


    # Testing

    def validate_mix(self, cipher_mix, last_mix=None, nr_parallel=None):
        """
        """
        try:
            hex_crypto_params, election_key = self.extract_header(cipher_mix)
            original_ciphers = cipher_mix['original_ciphers']
            mixed_ciphers = cipher_mix['mixed_ciphers']
            proof = cipher_mix['proof']
        except KeyError as error:
            err = 'Invalid mix format: \'%s\' missing' % error.args[0]
            raise InvalidMixError(err)
        if hex_crypto_params != self.cryptosys.hex_crypto_params():
            err = 'Cryptosystem mismatch'
            raise InvalidMixError(err)
        if last_mix and original_ciphers != last_mix['mixed_ciphers']:
            err = 'Not a mix of latest ciphers'
            raise InvalidMixError(err)

        if nr_parallel is None:
            nr_parallel = 0
        try:
            self.verify_mix(cipher_mix, nr_parallel=nr_parallel)
        except MixNotVerifiedError:
            raise

        return True


    @abstractmethod
    def verify_mix(self, cipher_mix, **kwargs):
        """
        """


    # Formats

    ############################################################################################
    #                                                                                          #
    #       By cipher-collection is meant a structure of the form                              #
    #                                                                                          #
    #       {                                                                                  #
    #           'original_ciphers': list[{'alpha': GroupElement, 'beta': GroupElement}],       #
    #           ['mixed_ciphers': list[{'alpha': GroupElement, 'beta': GroupElement}],]        #
    #           ['proof': ...]                                                                 #
    #           ...                                                                            #
    #       }                                                                                  #
    #                                                                                          #
    #       whereas by cipher-mix is meant a structure of the form                             #
    #                                                                                          #
    #       {                                                                                  #
    #           'header': {                                                                    #
    #                         ...,                                                             #
    #                         public: GroupElement                                             #
    #            },                                                                            #
    #           'original_ciphers': list[(GroupElement, GroupElement)],                        #
    #           'mixed_ciphers': list[(GroupElement, GroupElement)],                           #
    #           ['proof': ...]                                                                 #
    #       }                                                                                  #
    #                                                                                          #
    #       where 'public' is the running election's key and the rest fields of                #
    #       header refer to the underlying cryptosystem's parameters                           #
    #                                                                                          #
    ############################################################################################

    def _set_cipher_mix(self, cipher_collection):
        """
        Turns the provided cipher-collection into the corresponding cipher-mix

        If provided, the value of 'proof' will be direcelectitly extracted from the
        provided collection's homonymous field. If `mixed_ciphers` is not
        provided, then the output's corresponding value will be the same as
        that of `original_ciphers`

        :type cipher_collection: dict
        :rtype: dict
        """
        output = {}
        output.update({'header': self.header})
        output['original_ciphers'] = [(cipher['alpha'], cipher['beta'])
                for cipher in cipher_collection['original_ciphers']]
        try:
            output['mixed_ciphers'] = [(cipher['alpha'], cipher['beta'])
                for cipher in cipher_collection['mixed_ciphers']]
        except KeyError:
            output['mixed_ciphers'] = output['original_ciphers']
        proof = cipher_collection.get('proof')
        if proof:
            output['proof'] = proof
        return output

    def _extract_cipher_mix(self, cipher_mix):
        """
        Turns the provided cipher-mix into the corresponding cipher-collection

        If provided, the value of 'proof' will be directly extracted from the
        provided mix's homonymous field

        :type cipher_mix: dict
        :rtype: dict
        """
        output = {}
        output.update({'header': self.header})
        for key in ('original_ciphers', 'mixed_ciphers',):
            output[key] = [{'alpha': cipher[0], 'beta': cipher[1]}
                for cipher in cipher_mix[key]]
        proof = cipher_mix['proof']
        if proof:
            output['proof'] = proof
        return output

    def extract_header(self, cipher_mix):
        """
        Extracts from the header of the provided cipher-mix the parameters of
        the underlying cryptosystem as hexadecimals along with unhexifying
        inscribed election key
        """
        header = deepcopy(cipher_mix['header'])
        public = header.pop('public')
        election_key = self.cryptosys.hex_to_element(public)
        return header, election_key
