"""
"""

from zeus_core.crypto import mk_cryptosys

class Client(object):
    """
    """

    def __init__(self, crypto_config):
        self.cryptosys = mk_cryptosys(crypto_config)

    def get_cryptosys(self):
        return self.cryptosys
