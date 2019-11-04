"""
Tests in standalone fashion the vote-signing and
vote-signature-verification interface
"""

import pytest
import unittest
import json
from copy import deepcopy

from zeus_core.elections.decryption import Decryptor

class DummyDecryptor(Decryptor):
    """
    Minimal implementation of decryption interface for testing purposes
    """

    def __init__(self, election):
        self.election = election
        #
        # Not yet implemented
        #

class TestDecryption(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
    #
    # Not yet implemented
    #
        pass

    @classmethod
    def tearDownClass(cls):
        messages = cls.messages
        for i, message in enumerate(messages):
            if i == 0:
                print('\n' + message)
            else:
                print(message)

    def get_context(self):
        # cls = self.__class__
        # election = cls.election
        # cryptosys = cls.cryptosys
        # signer = cls.signer
        # verifier = cls.verifier
        # client = cls.client
        # messages = cls.messages
        #
        # return election, cryptosys, signer, verifier, client, messages
        #
        # Not yet implemented
        #
        pass

    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)

if __name__ == '__main__':
    print('\n================== Testing mixed ballots decryption ==================')
    unittest.main()
