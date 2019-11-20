"""
"""

from abc import ABCMeta, abstractmethod

from zeus_core.election.interfaces.key_manager import KeyManager
from zeus_core.election.interfaces.factor_managers import FactorGenerator
from .client import Client


class Trustee(Client, KeyManager, FactorGenerator, metaclass=ABCMeta):
    """
    """

    def __init__(self, crypto_config, keypair):
        self.keypair = keypair
        super().__init__(crypto_config)


    @abstractmethod
    def recv_mixed_ballots(self, mixed_ballots):
        """
        """

    @abstractmethod
    def send_trustee_factors(self, election_server):
        """
        """

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
