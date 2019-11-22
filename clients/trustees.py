"""
"""

from abc import ABCMeta, abstractmethod
from zeus_core.election.interfaces.factor_managers import FactorGenerator
from .generic import Client


class Trustee(Client, FactorGenerator, metaclass=ABCMeta):
    """
    """

    def store_keypair(self, keypair):
        """
        """
        self.keypair = keypair


    def get_keypair(self):
        """
        """
        return self.keypair


    def get_public_key(self):
        """
        """
        keypair = self.get_keypair()
        public_key = self.get_public_value(keypair)
        return public_key
