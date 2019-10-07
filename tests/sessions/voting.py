"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep

from zeus_core.utils import random_integer
from zeus_core.crypto.exceptions import (InvalidVoteError, InvalidSignatureError)

from tests.constants import choices, _2048_SYSTEM, _4096_SYSTEM
from tests.helpers import (make_voters, make_corrupted_public_key, make_vote,
    make_corrupted_signature_vote, corrupt_signature_structure,
    corrupt_implicit_signature)

def _exit(message, code=1):
    print(message)
    print('\nVoting session incomplete: CHECK FAILED\n')
    sys.exit(code)


if __name__=='__main__':

    print('\n--------------------- Voting Test Session ---------------------\n')

    voters = make_voters(10)
    system = _4096_SYSTEM

    print('Key generation...\n')
    sleep(.5)
    zeus_keypair = system.create_zeus_keypair()
    zeus_private_key, zeus_public_key = system.extract_keypair(zeus_keypair)
    trustees = system.generate_trustees(7)
    election_key = system.compute_election_key(trustees, zeus_keypair)

    # Validation of keys
    print('Validation of keys\n')

    valid = system.validate_election_key(election_key, trustees, zeus_keypair)
    if valid:
        print(' + Election key successfully validated')
    else:
        _exit(' - Valid election key failed to be validated')

    corrupted_zeus_keypair = system.create_zeus_keypair()
    corrupted_key_1 = system.compute_election_key(trustees, corrupted_zeus_keypair)
    invalid_1 = system.validate_election_key(corrupted_key_1, trustees, zeus_keypair)
    if not invalid_1:
        print(' + Corrupted zeus successfully detected')
    else:
        _exit(' - Corrupted zeus failed to be detected')

    corrupted_trustees = trustees[:]
    corrupted_trustees[-1] = make_corrupted_public_key(system)
    corrupted_key_2 = system.compute_election_key(corrupted_trustees, zeus_keypair)
    invalid_2 = system.validate_election_key(corrupted_key_2, trustees, zeus_keypair)
    if not invalid_2:
        print(' + Corrupted trustee sucessfully detected')
    else:
        _exit(' - Corrupted trustee failed to be detected'    )

    # Make votes
    print('\nVoting...\n')
    sleep(.5)
    votes = []

    for voter in voters[:8]:                        # 8 first votes valid
        vote = make_vote(voter, system, election_key)
        votes.append(vote)

    for voter in voters[-2:]:                       # 2 last votes invalid
        vote = make_vote(voter, system, election_key, invalid=True)
        votes.append(vote)

    # Validate submitted votes
    print('Vote validation\n')

    valid_votes = []
    invalid_votes = []

    for i in range(len(votes)):
        try:
            system.validate_submitted_vote(votes[i])
        except InvalidVoteError:
            if i < 8:
                _exit(' - Valid vote failed to be validated')
            else:
                print(' + Invalid vote successfully detected')
                invalid_votes.append(vote)
        else:
            if i < 8:
                print(' + Valid vote successfully validated')
                valid_votes.append(vote)
            else:
                _exit(' - Invalid vote failed to be detected')

    # Sign valid votes
    print('\nSigning votes...\n')
    sleep(.5)

    vote_signatures = []

    for i in range(len(valid_votes)):
        vote = valid_votes[i]

        nr_comments = random_integer(0, 5)
        comments = ['comment_%d_on_vote_%s'
            % (i, vote['fingerprint']) for i in range(nr_comments)]

        if i == 0:
            # Corrupt 1st signature by tempering proof encryption
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
    corrupted = corrupt_implicit_signature(signature, zeus_private_key, system)
    vote_signatures[2] = corrupted


    # Verify vote signatures
    print('Vote signatures validation\n')

    verified_signatures = []
    non_verified_signatures = []

    for i in range(len(vote_signatures)):
        signature = vote_signatures[i]

        if i == 0:
            try:
                system.verify_vote_signature(signature)
            except InvalidSignatureError:
                print(' + Invalid encryption proof successfully detected')
            else:
                _exit(' - Valid encryption proof erroneously invalidated')
        elif i == 1:
            try:
                system.verify_vote_signature(signature)
            except InvalidSignatureError:
                print(' + Invalid signature structure successfully detected')
            else:
                _exit(' - Valid signature structure erroneously invalidated')
        elif i == 2:
            try:
                system.verify_vote_signature(signature)
            except InvalidSignatureError:
                print(' + Invalid inscribed signature successfully detected')
            else:
                _exit(' - Valid inscribed signature erroneously invalidated')
        else:
            try:
                system.verify_vote_signature(signature)
            except InvalidSignatureError:
                _exit(' - Invalid vote signature failed to be detected')
            else:
                print(' + Vote signature successfully verified')

    print('\nVoting session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
