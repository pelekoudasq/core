import unittest

from tests.election.makers import mk_election
from zeus_core.election.exceptions import Abortion

class TestElection__Success(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        election = mk_election()
        cls.election = election

    def get_election(self):
        return __class__.election

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


class TestElection__Abortions(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        election = mk_election()
        cls.election = election

    def get_election(self):
        return __class__.election


if __name__ == '__main__':
    unittest.main()
