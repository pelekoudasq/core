"""
Tests the interfaces for vote signing and vote-signature verification
"""

import pytest
import json
from zeus_core.elections.validations import Validator
from tests.elections.utils import display_json, mk_voting_setup, adapt_vote

if __name__ == '__main__':
    election, clients = mk_voting_setup()
    cryptosys = election.get_cryptosys()
    validator = Validator(election)

    client = clients[0]

    # Test genuine vote validation
    vote = client.mk_genuine_vote()
    vote = adapt_vote(cryptosys, vote)
    validator.validate_genuine_vote(vote)

    # Test audit-vote validation

    audit_vote = client.mk_audit_vote()
    audit_vote = adapt_vote(cryptosys, audit_vote)
    missing, failed = validator.validate_audit_votes([vote,])
    assert not missing
    assert not failed
