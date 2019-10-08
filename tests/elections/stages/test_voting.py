import pytest
from copy import deepcopy
import time

from tests.elections.stages.abstracts import StageTester

from zeus_core.elections.exceptions import Abortion
from zeus_core.elections.stages import Uninitialized


import unittest

class TestVoting(StageTester, unittest.TestCase):

    # Setup

    def run_until_stage(self):
        self.launch_election()
        uninitialized = Uninitialized(self.election)
        uninitialized.run()
        creating = uninitialized.next()
        creating.run()
        self.voting = creating.next()

    # ...

    # Run whole stage and check updates

if __name__ == '__main__':
    print('\n=================== Testing election stage: Voting ===================')
    time.sleep(.6)
    unittest.main()



# Run stage and check for updates

# def test_stage_finalization():
#     assert all([election.get_cast_vote_index() == [],
#                 election.get_votes() == {},
#                 election.get_cast_votes() == {},
#                 election.get_audit_requests() == {},
#                 election.get_audit_publications() == [],
#                 election.get_excluded_voters() == {}])
#     voting.run()
#     # assert all([election.get_zeus_private_key() != None,
#     #             election.get_zeus_public_key() != None,
#     #             election.get_trustees() != {},
#     #             election.get_election_key() != None,
#     #             election.get_candidates() != [],
#     #             election.get_voters() != {},
#     #             election.get_audit_codes() != {},])




# # Client voting reference (INCOMPLETE!)
#
# def cast_vote(self, vote):
#     """
#     """
#     election = self._get_controller()
#
#     # voter_key = vote['voter_key']
#     # fingerprint = vote['fingerprint']
#     # voter_audit_code = vote['audit_code'] if 'audit_code' in vote else None
#     # voter_secret = vote['voter_secret'] if 'voter_secret' in vote else None
#     (_, _, voter_key, _, _, _, _, _, fingerprint,
#         voter_audit_code, voter_secret, _, _, _, _,) = self.extract_vote(vote)
#
#     voter = election.get_voter(voter_key)
#     voter_audit_codes = election.get_voter_audit_codes(voter_key)
#     if not voter and not voter_audit_codes:
#         err = 'Invalid voter key'
#         raise Abortion(err)
#     if not voter or not voter_audit_codes:
#         err = 'Voter audit code inconsistency'
#         raise Abortion(err)
#
#     audit_request = election.get_audit_request(fingeprint)
#
#     if voter_secret:
#         # This is an audit-publication
#         pass
#
#     if not voter_audit_code:
#         # ...
#         pass
#
#     if voter_audit_code not in voter_audit_codes: # Audit request submission
#         if audit_request:
#             err = "Audit request for vote [%s] already exists" % (fingeprint,)
#             raise Abortion(err)
#         vote['previous'] = ''
#         vote['index'] = None
#         vote['status'] = V_AUDIT_REQUEST
#         comments = self.custom_audit_request_message(vote)
#         signature = self.sign_vote(vote, comments)
#         vote['signature'] = signature
#         election.store_audit_request(fingerprint, voter_key)
#         election.store_votes((vote,))
#
#         return signature
#
#     else:                                          # Genuine vote submission
#         if election.get_vote(fingerprint):
#             err = "Vote [%s]"
#
#
# def sign_vote(self, vote, comments, cryptosys, zeus_private_key,
#         zeus_public_key, trustees, candidates):
#     """
#     NOTE: extract values of trustees' public keys before feeding them to this function!!!!
#     trustees = [cryptosys.get_value(trustee) for trustee in trustees]
#     """
#     textfied_vote = self.textify_vote(self, vote, comments, cryptosys,
#         zeus_public_key, trustees, candidates)
#     signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
#     _, exponent, c_1, c_2 = cryptosys.extract_signed_message(signed_vote)
#
#     vote_signature = self.format_vote_signature(textified_vote, exponent, c_1, c_2)
#
#     return vote_signature
#
# def format_vote_signature(self, textified_vote, exponent, c_1, c_2):
#     textified_vote += V_SEPARATOR
#     vote_signature += '%s\n%s\n%s\n' % (str(exponent), str(c_1), str(c_2))
#     return vote_signature
#
# def textify_vote(self, vote, comments,
#         cryptosys, zeus_public_key, trustees, candidates):
#
#     (crypto_params, election_key, _, alpha, beta, commitment, challenge, response,
#         fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)
#
#     t00 = status if status is not None else 'NONE'
#     t01 = V_FINGERPRINT + '%s' % fingerprint
#     t02 = V_INDEX + '%d' % (index if index is not None else 'NONE')
#     t03 = V_PREVIOUS + '%s' % (previous,) 	# '%s%s' % (V_PREVIOUS, previous)
#     t04 = V_ELECTION + '%s' % str(election_key)
#     t05 = V_ZEUS_PUBLIC + '%s' % str(zeus_public_key)
#     t06 = V_TRUSTEES + '%s' % ' '.join(str(_) for _ in trustees)
#     t07 = V_CANDIDATES + '%s' % ' % '.join('%s' % _.encode('utf-8') for _ in candidates)
#
#     t08, t09, t10 = cryptosys.textify_params(crypto_params)
#
#     t11 = V_ALPHA + '%s' % str(alpha)
#     t12 = V_BETA + '%s' % str(beta)
#     t13 = V_COMMITMENT + '%s' % str(commitment)
#     t14 = V_CHALLENGE + '%s' % str(challenge)
#     t15 = V_RESPONSE + '%s' % str(response)
#     t16 = V_COMMENTS + '%s' % (comments,)
#
#     textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
#         t09, t10, t11, t12, t13, t14, t15, t6))
#     return textified
#
# def validate_submitted_vote(self, cryptosys, vote):
#     """
#     Verifies the inscribed encryption proof, checks if the vote's
#     fingerprint is correct and returns the fingerprint
#
#     If not, it raises InvalidVoteError
#
#     :type vote: dict
#     :rtype: bytes
#     """
#     encrypted_ballot = vote['encrypted_ballot']
#     fingerprint = vote['fingerprint']
#
#     if not cryptosys.verify_encryption(encrypted_ballot):
#         err = 'Invalid ballot encryption'
#         raise InvalidVoteError(err)
#     if fingerprint != cryptosys.make_fingerprint(encrypted_ballot):
#         err = 'Invalid fingerprint'
#         raise InvalidVoteError(err)
#
#     return fingerprint
#
# def extract_vote(self, vote, encode_func, to_exponent=int):
#     """
#     """
#     crypto_params = vote['crypto']
#     election_key = vote['public']
#     voter_key = vote['voter']
#     alpha, beta, commitment, challenge, response = \
#         self.extract_encrypted_ballot(vote['encrypted_ballot'])
#     fingerprint = hash_encode(vote['fingerprint'])
#
#     audit_code = extract_value(vote, 'audit_code', int)
#     voter_secret = extract_value(vote, 'voter_secret', to_exponent) # mpz
#     previous = extract_value(vote, 'previous', hash_encode)
#     index = extract_value(vote, 'index', int)
#     status = extract_value(vote, 'status', str)
#     plaintext = extract_value(vote, 'plaintext', encode_func)
#
#     return (crypto_params, election_key, voter_key, alpha, beta, commitment,
#             challenge, response, fingerprint, audit_code, voter_secret,
#             previous, index, status, plaintext,)
#
# def extract_encrypted_ballot(self, cryptosys, encrypted_ballot):
#     ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
#     alpha, beta = cryptosys.extract_ciphertext(ciphertext)
#     commitment, challenge, response = cryptosys.extract_proof(proof)
#     return alpha, beta, commitment, challenge, response
#
# def vote_from_plaintext(self, cryptosys, election_key, voter_key,
#         plaintext, audit_code=None, publish=None):
#     """
#     """
#     plaintext = cryptosys.encode_integer(plaintext)
#     ciphertext, voter_secret = cryptosys._encrypt(encoded_plaintext,
#                     election_key, get_secret=True)
#     proof = cryptosys.prove_encryption(ciphertext, randomness)
#
#     encrypted_ballot = self.make_encrypted_ballot(cryptosys, ciphertext, proof)
#     fingerprint = self.make_fingerprint(cryptosys, encrypted_ballot)
#
#     vote = self.set_vote(cryptosys, election_key, voter_key,
#         encrypted_ballot, fingerprint, audit_code, publish, voter_secret)
#     return vote
#
#
# def vote_from_encoded_selection(self, cryptosys, election_key, voter_key,
#         encoded_selection, audit_code=None, publish=None):
#     """
#     """
#     encoded_selection = cryptosys.encode_integer(encoded_selection)
#     ciphertext, randomness = cryptosys._encrypt(encoded_selection,
#                     election_key, get_secret=True)
#     proof = cryptosys.prove_encryption(ciphertext, randomness)
#
#     encrypted_ballot = self.make_encrypted_ballot(cryptosys, ciphertext, proof)
#     fingerprint = cryptosys.make_fingerprint(cryptosys, encrypted_ballot)
#     voter_secret = randomness if publish else None
#
#     vote = self.set_vote(cryptosys, election_key, voter_key,
#         encrypted_ballot, fingerprint, audit_code, publish, voter_secret)
#     return vote
#
#
# def set_vote(self, cryptosys, election_key, voter_key, encrypted_ballot,
#         fingerprint, audit_code=None, publish=None, voter_secret=None,
#         previous=None, index=None, status=None, plaintext=None):
#     """
#     """
#     vote = {}
#
#     vote['crypto'] = cryptosys.parameters()
#     vote['public'] = election_key
#     vote['voter'] = voter_key
#     vote['encrypted_ballot'] = encrypted_ballot
#     vote['fingerprint'] = hash_decode(fingerprint)
#
#     if audit_code:
#         vote['audit_code'] = audit_code
#     if publish:
#         vote['voter_secret'] = voter_secret
#     if previous:
#         vote['index'] = index
#     if status:
#         vote['status'] = status
#     if plaintext:
#         vote['plaintext'] = plaintext
#
#     return vote
#
#
# def make_encrypted_ballot(self, cryptosys, election_key, ciphertext, proof):
#     encrypted_ballot = cryptosys.set_ciphertext_proof(ciphertext, proof)
#     return encrypted_ballot
#
#
# def make_fingerprint(self, cryptosys, ciphertext_proof):
#     """
#     """
#     fingerprint_params = self.get_fingerprint_params(cryptosys, ciphertext_proof)
#     fingerprint = hash_texts(*[str(_) for _ in fingerprint_params])
#     return fingerprint
#
# def get_fingerprint_params(self, cryptosys, ciphertext_proof):
#     """
#     """
#     ciphertext, proof = cryptosys.extract_ciphertext_proof(ciphertext_proof)
#     alpha, beta = cryptosys.extract_ciphertext(ciphertext)
#     commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
#     return alpha, beta, commitment, challenge, response
