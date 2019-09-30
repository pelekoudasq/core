import pytest

from crypto.exceptions import (InvalidVoteError, InvalidSignatureError)
from utils import random_integer

from tests.helpers import (make_voters, make_corrupted_public_key, make_vote,
    make_corrupted_signature_vote, corrupt_signature_structure, corrupt_implicit_signature)
from tests.constants import choices, _2048_SYSTEM, _4096_SYSTEM

# For each cryptosystem, prepare election, voters and votes

_2048_ZEUS_KEY = _2048_SYSTEM.create_zeus_keypair()
_2048_TRUSTEES = _2048_SYSTEM.generate_trustees(7)
_2048_ELECTION_KEY = _2048_SYSTEM.compute_election_key(_2048_TRUSTEES, _2048_ZEUS_KEY)
_2048_VOTERS = make_voters(10)
_2048_VOTES = []
for voter in _2048_VOTERS[:8]:                                                  # 8 first votes valid
    vote = make_vote(voter, _2048_SYSTEM, _2048_ELECTION_KEY)
    _2048_VOTES.append(vote)
for voter in _2048_VOTERS[-2:]:                                                 # 2 last votes invalid
    vote = make_vote(voter, _2048_SYSTEM, _2048_ELECTION_KEY, invalid=True)
    _2048_VOTES.append(vote)
_2048_VALID_VOTES = _2048_VOTES[:8]
_2048_INVALID_VOTES = _2048_VOTES[-2:]

_4096_ZEUS_KEY = _4096_SYSTEM.create_zeus_keypair()
_4096_TRUSTEES = _4096_SYSTEM.generate_trustees(7)
_4096_ELECTION_KEY = _4096_SYSTEM.compute_election_key(_4096_TRUSTEES, _4096_ZEUS_KEY)
_4096_VOTERS = make_voters(10)
_4096_VOTES = []
for voter in _4096_VOTERS[:8]:                                                  # 8 first votes valid
    vote = make_vote(voter, _4096_SYSTEM, _4096_ELECTION_KEY)
    _4096_VOTES.append(vote)
for voter in _4096_VOTERS[-2:]:                                                 # 2 last votes invalid
    vote = make_vote(voter, _4096_SYSTEM, _4096_ELECTION_KEY, invalid=True)
    _4096_VOTES.append(vote)
_4096_VALID_VOTES = _4096_VOTES[:8]
_4096_INVALID_VOTES = _4096_VOTES[-2:]


# Validation of keys

__system__election_key__trustees__zeus_keypair = [
    (_2048_SYSTEM, _2048_ELECTION_KEY, _2048_TRUSTEES, _2048_ZEUS_KEY),
    (_4096_SYSTEM, _4096_ELECTION_KEY, _4096_TRUSTEES, _4096_ZEUS_KEY),
]

@pytest.mark.parametrize('system, election_key, trustees, zeus_keypair',
    __system__election_key__trustees__zeus_keypair)
def test_election_key_validation(system, election_key, trustees, zeus_keypair):
    assert system.validate_election_key(election_key, trustees, zeus_keypair)

__system__election_key__trustees = [
    (_2048_SYSTEM, _2048_ELECTION_KEY, _2048_TRUSTEES),
    (_4096_SYSTEM, _4096_ELECTION_KEY, _4096_TRUSTEES),
]

@pytest.mark.parametrize('system, election_key, trustees',
    __system__election_key__trustees)
def test_corrupted_zeus_detection(system, election_key, trustees):
    corrupted_zeus = system.create_zeus_keypair()
    valid = system.validate_election_key(election_key, trustees, corrupted_zeus)
    assert not valid

__system__election_key__trustees = [
    (_2048_SYSTEM, _2048_ELECTION_KEY, _2048_TRUSTEES),
    (_4096_SYSTEM, _4096_ELECTION_KEY, _4096_TRUSTEES),
]

@pytest.mark.parametrize('system, election_key, trustees',
    __system__election_key__trustees)
def test_corrupted_zeus_detection(system, election_key, trustees):
    corrupted_zeus = system.create_zeus_keypair()
    valid = system.validate_election_key(election_key, trustees, corrupted_zeus)
    assert not valid

@pytest.mark.parametrize('system, election_key, trustees, zeus_keypair',
    __system__election_key__trustees__zeus_keypair)
def test_corrupted_trustee_detection(system, election_key, trustees, zeus_keypair):
    corrupted_trustees = trustees[:]
    corrupted_trustees[-1] = make_corrupted_public_key(system)
    valid = system.validate_election_key(election_key, corrupted_trustees, zeus_keypair)
    assert not valid


# Validation of submitted votes

__system__votes__valid_votes__invalid_votes = [
    (_2048_SYSTEM, _2048_VOTES, _2048_VALID_VOTES, _2048_INVALID_VOTES),
    (_4096_SYSTEM, _4096_VOTES, _4096_VALID_VOTES, _4096_INVALID_VOTES)
]

@pytest.mark.parametrize('system, votes, valid_votes, invalid_votes',
    __system__votes__valid_votes__invalid_votes)
def test_submitted_votes_validation(system, votes, valid_votes, invalid_votes):
    valids = []
    invalids = []
    for vote in votes:
        try:
            system.validate_submitted_vote(vote)
        except InvalidVoteError:
            invalids.append(vote)
        else:
            valids.append(vote)
    assert valid_votes == valids and invalid_votes == invalids


# Verification of vote signatures

_2048_VOTE_SIGNATURES = []
_4096_VOTE_SIGNATURES = []
__system__vote_signatures = []

for (system, election_key, zeus_keypair, trustees, valid_votes, vote_signatures) in (
    (_2048_SYSTEM, _2048_ELECTION_KEY, _2048_ZEUS_KEY, _2048_TRUSTEES, _2048_VALID_VOTES, _2048_VOTE_SIGNATURES),
    (_4096_SYSTEM, _4096_ELECTION_KEY, _4096_ZEUS_KEY, _4096_TRUSTEES, _4096_VALID_VOTES, _4096_VOTE_SIGNATURES)):

    # Sign valid votes and corrupt the first 3 signatures in various ways

    for i in range(len(valid_votes)):
        vote = valid_votes[i]

        nr_comments = random_integer(0, 5)
        comments = ['comment_%d_on_vote_%s'
            % (i, vote['fingerprint']) for i in range(nr_comments)]

        if i == 0:
            # Corrupt 1st signature by tampering proof encryption
            vote_signature = make_corrupted_signature_vote(system, vote,
                    comments, election_key, zeus_keypair, trustees, choices)
        else:
            vote_signature = system.sign_vote(
                vote, comments, election_key, zeus_keypair, trustees, choices)

        vote_signatures.append(vote_signature)

    # Corrupt 2nd and 3rd signature

    signature = vote_signatures[1]
    corrupted = corrupt_signature_structure(signature)
    vote_signatures[1] = corrupted

    signature = vote_signatures[2]
    zeus_private_key = system._get_private(zeus_keypair)
    corrupted = corrupt_implicit_signature(signature, zeus_private_key, system)
    vote_signatures[2] = corrupted              # must raise InvalidSignatureError

    __system__vote_signatures.append((system, vote_signatures))


@pytest.mark.parametrize('system, vote_signatures', __system__vote_signatures)
def test_vote_signature_verification(system, vote_signatures):
    for i in range(len(vote_signatures)):
        signature = vote_signatures[i]
        if 0 <= i <= 2:
            with pytest.raises(InvalidSignatureError):
                system.verify_vote_signature(signature)
        else:
            assert system.verify_vote_signature(signature)
