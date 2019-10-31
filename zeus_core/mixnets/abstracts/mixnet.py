from abc import ABCMeta, abstractmethod

class Mixnet(object, metaclass=ABCMeta):
    """
    Abstract base class for mixnets
    """

    __slots__ = ('__cryptosys', '__election_key', '__group', '__header')

    def __init__(self, cryptosys, election_key=None):
        self.__cryptosys = cryptosys
        self.__group = cryptosys.group
        header = {}
        header.update(cryptosys.hex_parameters())
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


    # Core

    @abstractmethod
    def mix_ciphers(self, original_mix, **kwargs):
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


    # Encryption

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

        If provided, the value of 'proof' will be directly extracted from the
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

    def retrieve_election_key(self, cipher_mix):
        """
        Unhexifies and returns the election key as inscribed
        in the provided cipher-mix
        """
        public = self.cryptosys.hex_to_element(cipher_mix['header']['public'])
        return public
