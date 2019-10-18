"""
Tests the interfaces for vote signing and vote-signature verification
"""

import pytest
import json
from zeus_core.elections.signatures import Signer, Verifier
from tests.elections.utils import display_json, mk_voting_setup, adapt_vote

if __name__ == '__main__':
    election, clients = mk_voting_setup()
    cryptosys = election.get_cryptosys()
    signer = Signer(election)
    verifier = Verifier(election)

    client = clients[0]

    mk_genuine_vote = client.mk_genuine_vote
    mk_audit_request = client.mk_audit_request
    mk_audit_vote = client.mk_audit_vote
    for vote in (mk_genuine_vote(), mk_audit_request(), mk_audit_vote()):
        display_json(vote)
        vote = adapt_vote(cryptosys, vote)
        display_json(vote)
        # textified_vote = signer.textify_vote(vote)
        # print(textified_vote)
        vote_signature = signer.sign_vote(vote, ['some comment...'])
        print(vote_signature)
        assert verifier.verify_vote_signature(vote_signature)
