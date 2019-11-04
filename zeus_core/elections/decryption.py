"""
Contains standalone interface for mixed ballots decryption
"""

from abc import ABCMeta, abstractmethod


class Decryptor(object, metaclass=ABCMeta):
    """
    Mixed ballots decryption interface to election server
    """

    def compute_trustee_factors(self, trustee):
        pass

    def validate_trustee_factors(self, trustee):
        pass

    # Formats

    #####################################################################
    #                                                                   #
    #       By factor is meant a dictionary of the form                 #
    #                                                                   #
    #       {                                                           #
    #         'data': GroupElement,                                     #
    #         'proof': dict                                             #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'proof' is usually a Schnorr-proof       #
    #                                                                   #
    #####################################################################

    def set_factor(self, element, proof):
        """
        """
        factor = {}
        factor['data'] = element
        factor['proof'] = proof
        return factor


    def extract_factor(self, factor):
        """
        """
        element = factor['data']
        proof = factor['proof']
        return element, proof


    #####################################################################
    #                                                                   #
    #       By trustee-factors is meant a dictionary of the form        #
    #                                                                   #
    #       {                                                           #
    #           'public': GroupElement,                                 #
    #           'factors': list[factor]                                 #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'public' is thought of as the            #
    #       trustee's public key                                        #
    #                                                                   #
    #####################################################################

    def set_trustee_factors(self, public, factors):
        """
        """
        trustee_factors = {}
        trustee_factors['public'] = public
        trustee_factors['factors'] = factors
        return trustee_factors

    def extract_trustee_factors(self, trustee_factors):
        """
        """
        public = trustee_factors['public']
        factors = trustee_factors['factors']
        return public, factors
