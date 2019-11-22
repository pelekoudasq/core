"""
"""
from zeus_core.election.interfaces.key_manager import KeyManager


class Client(KeyManager):
    """
    """

    def set_cryptosys(self, cryptosys):
        """
        """
        self.cryptosys = cryptosys


    def get_cryptosys(self):
        """
        """
        return self.cryptosys
