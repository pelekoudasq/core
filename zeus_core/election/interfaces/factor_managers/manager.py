"""
"""

from abc import ABCMeta, abstractmethod


class FactorManager(object, metaclass=ABCMeta):
    """
    """

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


    #####################################################################
    #                                                                   #
    #       By factor-collection is meant a dictionary of the form      #
    #                                                                   #
    #       {                                                           #
    #           'public': GroupElement,                                 #
    #           'factors': list[factor]                                 #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'public' is thought of as the            #
    #       factor-manager's public key                                 #
    #                                                                   #
    #####################################################################


    def set_factor_collection(self, public, factors):
        """
        """
        factor_collection = {}
        factor_collection['public'] = public
        factor_collection['factors'] = factors

        return factor_collection


    def extract_factor_collection(self, factor_collection):
        """
        """
        public = factor_collection['public']
        factors = factor_collection['factors']

        return public, factors


    def serialize_factor_collection(self, factor_collection):
        """
        """
        public, factors = self.extract_factor_collection(factor_collection)

        public = self.serialize_public_key(public)
        serialize_factor = self.serialize_factor
        factors = [serialize_factor(_) for _ in factors]

        serialized = self.set_factor_collection(public, factors)
        return serialized


    def deserialize_factor_collection(self, factor_collection):
        """
        """
        public, factors = self.extract_factor_collection(factor_collection)

        public = self.deserialize_public_key(public)
        deserialize_factor = self.deserialize_factor
        factors = [deserialize_factor(_) for _ in factors]

        deserialized = self.set_factor_collection(public, factors)
        return deserialized
