"""
Tests the interfaces for vote signing and vote-signature verification
"""

import pytest
from zeus_core.elections.signatures import Signer, Verifier
from tests.elections.utils import mk_voting_setup

if __name__ == '__main__':
    election, nr_candidates, clients = mk_voting_setup()
    signer = Signer(election)
    verifier = Verifier(election)
    vote, _, _, _ = clients[0].mk_random_vote(nr_candidates)
    for key in vote:
        print(key, type(vote[key]))
    print()
    for key in vote['encrypted_ballot']:
        print(key, type(vote['encrypted_ballot'][key]))
    # print(vote)
