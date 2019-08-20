from abc import ABCMeta, abstractmethod

class MixnetError(Exception):
    """
    """
    pass


class Mixnet(object, metaclass=ABCMeta):
    """
    Abstract class for mixnets
    """

    @abstractmethod
    def extract_mix(self, mixed_collection):
        """
        :type mixed_collection: list
        :rtype: list
        """

    @abstractmethod
	def prepare_mix(self, cipher_collection):
	    """
        :type cipher_collection: list
        :rtype: list
	    """

    def validate_mixes(self, mixes):
	        result = True
	        for mix in mixes:
	            #TODO validate if original_ciphers != previous_mixed:
	            result = result and self.validate_mix(mix)
	        return result


    # API

	@abstractmethod
	def validate_mix(self, mix, original_ciphertexts):
	    """
	    Verify a mix

	    :type: mix
        :type original_ciphertexts: list[mix]
	    :rtype: bool
	    """

	@abstractmethod
	def mix(self):
	    """
	    Mixing

        :type
        :rtype: list[mix]

	    Parameters
	    ----------
	    last_mix: list
	        mix

	    Returns
	    -------
	    list
	        of mixes.
	    """
	    pass


    @classmethod
	@abstractmethod
	def supports_cryptosystem(cls, cryptosys):
	    """
	    Decide whether or not mix module is able to mix ciphertexts generated from
	    the provided cryptosystem instance

        :type cryptosys:
        :rtype: bool
	    """
	    pass
