"""
"""

from abc import ABCMeta, abstractmethod
from zeus_core.election.interfaces.signatures import Verifier
from .generic import Client


class Voter(Client, Verifier, metaclass=ABCMeta):
    """
    """

    def __init__(self, name, weight):
        """
        """
        self.name = name
        self.weight = weight


    def get_name(self):
        """
        """
        return self.name


    def get_weight(self):
        """
        """
        return self.weight


    def store_election_key(self, election_key):
        """
        """
        self.election_key = election_key


    def get_election_key(self):
        """
        """
        return self.election_key


    def store_candidates(self, candidates):
        """
        """
        self.candidates = candidates


    def get_candidates(self):
        """
        """
        return self.candidates


    def store_voter_key(self, voter_key):
        """
        """
        self.voter_key = voter_key


    def get_voter_key(self):
        """
        """
        return self.voter_key


    def store_audit_codes(self, audit_codes):
        """
        """
        self.audit_codes = audit_codes


    def get_audit_codes(self):
        """
        """
        return self.audit_codes
