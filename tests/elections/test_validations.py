"""
Tests the interface for vote validation
"""

import pytest
import json
from zeus_core.elections.validations import Validator
from zeus_core.elections.exceptions import InvalidVoteError
from tests.elections.utils import display_json, mk_voting_setup, adapt_vote

if __name__ == '__main__':
    election, clients = mk_voting_setup()
    cryptosys = election.get_cryptosys()
    validator = Validator(election)

    client = clients[0]

    # Genuine vote validation

    # Valid case
    vote = client.mk_genuine_vote()
    vote = adapt_vote(cryptosys, vote)
    try:
        validator.validate_genuine_vote(vote)
    except:
        print('[-] Valid vote erroneously invalidated')
    else:
        print('[+] Vote successfully validated')

    # Unverified proof of encryption
    vote = client.mk_genuine_vote(corrupt_proof=True)
    vote = adapt_vote(cryptosys, vote)
    try:
        validator.validate_genuine_vote(vote)
    except InvalidVoteError:
        print('[+] Invalid vote successfully detected (unverified proof)')
    else:
        print('[-] Invalid vote failed to be detected')

    # Wrong fingerprint
    vote = client.mk_genuine_vote(corrupt_fingerprint=True)
    vote = adapt_vote(cryptosys, vote)
    try:
        validator.validate_genuine_vote(vote)
    except InvalidVoteError:
        print('[+] Invalid vote successfully detected (wrong fingerprint)')
    else:
        print('[-] Invalid vote failed to be detected')


    # Test audit-vote validation

    audit_vote = client.mk_audit_vote()
    audit_vote = adapt_vote(cryptosys, audit_vote)
    missing, failed = validator.validate_audit_votes(audit_votes=[audit_vote,])
    try:
        assert not missing and not failed
    except AssertionError:
        print('[-] Valid audit-vote erroneously invalidated')
    else:
        print('[+] Audit-vote successfully validated')

    # Delete voter's secret so that it be classified as missing
    audit_vote_1 = clients[1].mk_audit_vote(missing=True)
    audit_vote_1 = adapt_vote(cryptosys, audit_vote_1)

    # Corrupt proof so that encryption verification fails
    audit_vote_2 = clients[2].mk_audit_vote(corrupt_proof=True)
    audit_vote_2 = adapt_vote(cryptosys, audit_vote_2)

    # Corrupt alpha so that voter's secret verification fails
    audit_vote_3 = clients[3].mk_audit_vote(corrupt_alpha=True)
    audit_vote_3 = adapt_vote(cryptosys, audit_vote_3)

    # Dramatically reduce number of candidates so that decrypting the ballot
    # with the voter's secret exceeds max-gamma encoding of their number
    election.candidates = election.get_candidates()[:1]
    fake_nr_candidates = len(election.candidates)
    audit_vote_4 = clients[4].mk_audit_vote(corrupt_encoding=True,
        fake_nr_candidates=fake_nr_candidates)
    audit_vote_4 = adapt_vote(cryptosys, audit_vote_4)

    missing, failed = validator.validate_audit_votes(audit_votes=[
        audit_vote_1, audit_vote_2, audit_vote_3, audit_vote_4,])

    try:
        assert audit_vote_1 == missing.pop(0)
    except AssertionError:
        print('[-] Audit-vote with missing secret failed to be detected')
    else:
        print('[+] Audit-vote with missing secret successfully detected')
    try:
        assert audit_vote_2 == failed.pop(0)
    except AssertionError:
        print('[-] Audit-proof with invalid encryption failed to be detected')
    else:
        print('[+] Audit-proof with invalid encryption successfully detected')
    try:
        assert audit_vote_3 == failed.pop(0)
    except AssertionError:
        print('[-] Audit-proof with invalid secret failed to be detected')
    else:
        print('[+] Audit-proof with invalid secret successfully detected')
    try:
        assert audit_vote_4 == failed.pop(0)
    except AssertionError:
        print('[-] Audit-proof exceeding max-gamma encoding failed to be detected')
    else:
        print('[+] Audit-proof exceeding max-gamma encoding successfully detected')

    assert missing == []
    assert failed == []
