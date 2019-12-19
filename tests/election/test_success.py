"""
Tests successfull election flow via election exports
"""

import unittest

from tests.election.makers import mk_election
from zeus_core.election.exceptions import Abortion


class TestSuccess(unittest.TestCase):
    """
    """

    @classmethod
    def setUpClass(cls):
        election = mk_election()
        cls.election = election
        cls.messages = []

    @classmethod
    def tearDownClass(cls):
        print('\n')
        for message in cls.messages:
            print(message)

    def get_election(self):
        return __class__.election


    def test_0_uninitialized(self):
        election = self.get_election()
        
        uninitialized = election._get_current_stage()
        election._run(uninitialized)
        
        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
            }

    
    def test_1_creating(self):
        election = self.get_election()
        
        uninitialized = election._get_current_stage()
        creating = uninitialized.next()
        election._run(creating)

        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
                'zeus_public': election.get_hex_zeus_public_key(),
                'zeus_key_proof': election.get_hex_zeus_key_proof(),
                'trustees': election.get_trustees_serialized(),
                'election_key': election.get_election_key_serialized(),
                'candidates': election.get_candidates(),
                'voters': election.get_voters(),
                'audit_codes': election.get_audit_codes()
            }


    def test_2_voting(self):
        election = self.get_election()
        
        creating = election._get_current_stage()
        voting = creating.next()
        election._run(voting)

        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
                'zeus_public': election.get_hex_zeus_public_key(),
                'zeus_key_proof': election.get_hex_zeus_key_proof(),
                'trustees': election.get_trustees_serialized(),
                'election_key': election.get_election_key_serialized(),
                'candidates': election.get_candidates(),
                'voters': election.get_voters(),
                'audit_codes': election.get_audit_codes(),
                'votes': voting.serialized_votes,
                'cast_vote_index': election.get_cast_vote_index(),
                'cast_votes': election.get_cast_votes(),
                'audit_requests': voting.serialized_audit_requests,
                'audit_publications': voting.serialized_audit_publications,
                'excluded_voters': election.get_excluded_voters()
            }
    

    def test_3_mixing(self):
        election = self.get_election()
        
        voting = election._get_current_stage()
        mixing = voting.next()
        election._run(mixing)

        # Store here so that subsequent tests have 
        # access to the current stage's attributes
        __class__.voting = voting

        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
                'zeus_public': election.get_hex_zeus_public_key(),
                'zeus_key_proof': election.get_hex_zeus_key_proof(),
                'trustees': election.get_trustees_serialized(),
                'election_key': election.get_election_key_serialized(),
                'candidates': election.get_candidates(),
                'voters': election.get_voters(),
                'audit_codes': election.get_audit_codes(),
                'votes': voting.serialized_votes,
                'cast_vote_index': election.get_cast_vote_index(),
                'cast_votes': election.get_cast_votes(),
                'audit_requests': voting.serialized_audit_requests,
                'audit_publications': voting.serialized_audit_publications,
                'excluded_voters': election.get_excluded_voters(),
                'mixes': election.do_get_all_mixes()[1:]
            }
    

    def test_4_decrypting(self):
        election = self.get_election()
        
        mixing = election._get_current_stage()
        decrypting = mixing.next()
        election._run(decrypting)

        voting = __class__.voting

        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
                'zeus_public': election.get_hex_zeus_public_key(),
                'zeus_key_proof': election.get_hex_zeus_key_proof(),
                'trustees': election.get_trustees_serialized(),
                'election_key': election.get_election_key_serialized(),
                'candidates': election.get_candidates(),
                'voters': election.get_voters(),
                'audit_codes': election.get_audit_codes(),
                'votes': voting.serialized_votes,
                'cast_vote_index': election.get_cast_vote_index(),
                'cast_votes': election.get_cast_votes(),
                'audit_requests': voting.serialized_audit_requests,
                'audit_publications': voting.serialized_audit_publications,
                'excluded_voters': election.get_excluded_voters(),
                'mixes': election.do_get_all_mixes()[1:],
                'trustee_factors': election.get_all_factors()
            }
    

    def test_5_finished(self):
        election = self.get_election()
        
        decrypting = election._get_current_stage()
        finished = decrypting.next()
        election._run(finished)

        voting = __class__.voting

        assert election._get_exports() == {
                'cryptosystem': election.get_crypto_hex(),
                'mixnet': election.get_mixnet_type(),
                'zeus_public': election.get_hex_zeus_public_key(),
                'zeus_key_proof': election.get_hex_zeus_key_proof(),
                'trustees': election.get_trustees_serialized(),
                'election_key': election.get_election_key_serialized(),
                'candidates': election.get_candidates(),
                'voters': election.get_voters(),
                'audit_codes': election.get_audit_codes(),
                'votes': voting.serialized_votes,
                'cast_vote_index': election.get_cast_vote_index(),
                'cast_votes': election.get_cast_votes(),
                'audit_requests': voting.serialized_audit_requests,
                'audit_publications': voting.serialized_audit_publications,
                'excluded_voters': election.get_excluded_voters(),
                'mixes': election.do_get_all_mixes()[1:],
                'trustee_factors': election.get_all_factors(),
                'results': election.get_results(),
                'status': election.get_status(),
                'fingerprint': election.get_fingerprint(),
                'report': election.get_report()
            }


if __name__ == '__main__':
    unittest.main()
