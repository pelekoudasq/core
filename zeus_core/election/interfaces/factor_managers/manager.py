"""
"""

from abc import ABCMeta, abstractmethod


class FactorManager(object, metaclass=ABCMeta):
    """
    """

    #####################################################################
    #                                                                   #
    #       By factor is meant a dictionary of the form                 #
    #                                                                   #
    #       {                                                           #
    #         'data': GroupElement,                                     #
    #         'proof': dict                                             #
    #       }                                                           #
    #                                                                   #
    #       where 'proof' is thought of as a Chaum-Pedersen-proof       #
    #                                                                   #
    #####################################################################


    @abstractmethod
    def get_cryptosys():
        """
        """

    @abstractmethod
    def get_keypair(self):
        """
        """

    @abstractmethod
    def get_key_value(public_key):
        """
        """

    @abstractmethod
    def serialize_public_key(self, public_key):
        """
        """

    def get_group(self):
        """
        """
        cryptosys = self.get_cryptosys()
        return cryptosys.group


    def set_factor(self, data, proof):
        """
        """
        factor = {}

        factor['data'] = data
        factor['proof'] = proof

        return factor


    def extract_factor(self, factor):
        """
        """
        data = factor['data']
        proof = factor['proof']

        return data, proof


    def serialize_factor(self, factor):
        """
        """
        cryptosys = self.get_cryptosys()

        data, proof = self.extract_factor(factor)
        data = data.to_int()
        proof = cryptosys.serialize_chaum_pedersen_proof(proof)

        serialized = self.set_factor(data, proof)
        return serialized


    def deserialize_factor(self, factor):
        """
        """
        cryptosys = self.get_cryptosys()

        data, proof = self.extract_factor(factor)
        data = cryptosys.int_to_element(data)
        proof = cryptosys.deserialize_chaum_pedersen_proof(proof)

        deserialized = self.set_factor(data, proof)
        return deserialized
