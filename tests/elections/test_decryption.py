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
        pass

    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)

if __name__ == '__main__':
    print('\n================== Testing mixed ballots decryption ==================')
    unittest.main()
