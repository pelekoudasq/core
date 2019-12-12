"""
Tests in standalone fashion the decryption interface
"""

import pytest
import unittest
import json
from copy import deepcopy

from zeus_core.election.interfaces.decryption import Decryptor

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
        print('\n')
        for message in cls.messages:
            print(message)

    def get_context(self):
        pass

    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)

if __name__ == '__main__':
    print('\n================== Testing mixed ballots decryption ==================')
    unittest.main()
