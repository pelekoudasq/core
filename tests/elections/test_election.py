import unittest

from tests.elections.utils import mk_election

class TestElection(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        election = mk_election()
        cls.election = election

    def get_election(self):
        cls = self.__class__
        election = cls.election
        return election

    def test_0_uninitialized(self):
        assert self.get_election() is not None

    def test_1_creating(self):
        pass

    def test_2_voting(self):
        pass

    def test_3_mixing(self):
        pass

    def test_4_decrypting(self):
        pass

    def test_5_finished(self):
        pass

if __name__ == '__main__':
    unittest.main()
