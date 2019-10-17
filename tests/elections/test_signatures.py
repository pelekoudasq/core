"""
Tests the interfaces for vote signing and vote-signature verification
"""

import pytest
import json
from zeus_core.elections.signatures import Signer, Verifier
from tests.elections.utils import mk_voting_setup

def trim(vote, length=16):
    """
    """
    trim_value = lambda value: int(f'{value}'[:length]) \
        if type(value) is not str else f'{value}'[:length]
    trimmed_vote = {}
    for key, value in vote.items():
        trimmed_vote[key] = trim_value(value) if type(value) is not dict \
            else trim(value, length=length)
    return trimmed_vote

def display_vote(vote, length=16, trimmed=True):
    """
    Admits JSON (before or after adapmtment indifferently)
    """
    to_display = trim(vote, length=length) if trimmed else vote
    print(json.dumps(to_display, sort_keys=False, indent=4))

def adapt_vote(cryptosys, vote, serialize=True):
    """
    Simulates vote adaptment (no checks, only key rearrangement
    and values deserialization)
    """
    cast_element = cryptosys.int_to_element if serialize else lambda x: x
    cast_exponent = cryptosys.int_to_exponent if serialize else lambda x: x

    encrypted_ballot = vote['encrypted_ballot']
    public = encrypted_ballot.pop('public')
    alpha = encrypted_ballot.pop('alpha')
    beta = encrypted_ballot.pop('beta')
    commitment = encrypted_ballot.pop('commitment')
    challenge = encrypted_ballot.pop('challenge')
    response = encrypted_ballot.pop('response')
    vote['crypto'] = encrypted_ballot
    vote['public'] = public
    vote['encrypted_ballot'] = {
        'ciphertext': {
            'alpha': cast_element(alpha),
            'beta': cast_element(beta)
        },
        'proof': {
            'commitment': cast_element(commitment),
            'challenge': cast_exponent(challenge),
            'response': cast_exponent(response),
        }
    }
    return vote

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
        # display_vote(vote)
        vote = adapt_vote(cryptosys, vote)
        # display_vote(vote)
        # textified_vote = signer.textify_vote(vote)
        # print(textified_vote)
        vote_signature = signer.sign_vote(vote, ['some comment...'])
        # print(vote_signature)
        assert verifier.verify_vote_signature(vote_signature)
