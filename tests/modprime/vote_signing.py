from gmpy2 import mpz

from crypto.modprime import ModPrimeCrypto, ModPrimeElement
from crypto.constants import _4096_PRIME, _4096_PRIMITIVE
from crypto.utils import random_integer
from crypto.exceptions import InvalidVoteError, InvalidStructureError,\
    InvalidSignatureError, InvalidEncryptionError
from crypto.constants import V_FINGERPRINT,\
    V_PREVIOUS, V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES,\
    V_MODULUS, V_GENERATOR, V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT,\
    V_CHALLENGE, V_RESPONSE, V_COMMENTS, V_INDEX, V_CAST_VOTE,\
    V_AUDIT_REQUEST, V_PUBLIC_AUDIT, V_PUBLIC_AUDIT_FAILED

VOTER_KEY_CEIL = 2 ** 256
PLAINTEXT_CEIL = 2 ** 512

def make_voters(nr_voters):
    return ['%x' % random_integer(2, VOTER_KEY_CEIL) for _ in range(nr_voters)]

def make_corrupted_public_key():
    corrupted_keypair = system.keygen()
    return system._extract_public(corrupted_keypair)

def make_vote(voter, invalid=False):
    plaintext = random_integer(2, PLAINTEXT_CEIL)
    vote = system.vote(election_key, voter, plaintext)
    if invalid:
        vote['fingerprint'] = vote['fingerprint'] + '__corrupted_part'
    return vote

def make_corrupted_signature_vote(system, vote, comments, election_key,
                            zeus_keypair, trustees, choices):
    """
    Purpose of this function is to create a corrupted vote signature, such that
    InvalidEncryptionError gets raised upon validation.
    """
    __p, __q, __g = system._parameters()

    election_key = system._extract_value(election_key)

    zeus_private_key, zeus_public_key = system._extract_keypair(zeus_keypair)
    zeus_public_key = system._extract_value(zeus_public_key)

    _, encrypted, fingerprint, _, _, previous, index, status, _ = system._extract_vote(vote)

    alpha, beta, commitment, challenge, response = system._extract_fingerprint_params(encrypted)

    # Corrupt alpha and index
    alpha = ModPrimeElement(alpha.value + 1, __p)
    index = 1

    trustees = [system._extract_value(trustee) for trustee in trustees]

    m00 = status if status is not None else 'NONE'
    m01 = '%s%s' % (V_FINGERPRINT, fingerprint)
    m02 = '%s%s' % (V_INDEX, ('%d' % index) if index is not None else 'NONE')
    m03 = '%s%s' % (V_PREVIOUS, (previous,)) 	# '%s%s' % (V_PREVIOUS, previous)
    m04 = '%s%s' % (V_ELECTION, str(election_key))
    m05 = '%s%s' % (V_ZEUS_PUBLIC, str(zeus_public_key))
    m06 = '%s%s' % (V_TRUSTEES, ' '.join(str(_) for _ in trustees))
    m07 = '%s%s' % (V_CANDIDATES, ' % '.join('%s' % _.encode('utf-8') for _ in choices))
    m08 = '%s%s' % (V_MODULUS, str(__p))
    m09 = '%s%s' % (V_ORDER, str(__q))
    m10 = '%s%s' % (V_GENERATOR, str(__g))
    m11 = '%s%s' % (V_ALPHA, str(alpha))
    m12 = '%s%s' % (V_BETA, str(beta))
    m13 = '%s%s' % (V_COMMITMENT, str(commitment))
    m14 = '%s%s' % (V_CHALLENGE, str(challenge))
    m15 = '%s%s' % (V_RESPONSE, str(response))
    m16 = '%s%s' % (V_COMMENTS, (comments,))

    message = '\n'.join((m00, m01, m02, m03, m04, m05, m06, m07,\
        m08, m09, m10, m11, m12, m13, m14, m15, m16))

    signed_message = system.sign_text_message(message, zeus_private_key)
    message, exponent, c_1, c_2 = system._extract_signed_message(signed_message)
    exponent, c_1, c_2 = str(exponent), str(c_1), str(c_2)

    vote_signature = message
    vote_signature += '\n-----------------\n'
    vote_signature += '%s\n%s\n%s\n' % (exponent, c_1, c_2)

    return vote_signature

def corrupt_signature_structure(vote_signature):
    """
    Corrupts vote signature by invalidating the structure of the inscribed,
    message so that InvalidStructureError gets raised upon validation
    """
    message, _, exponent, c_1, c_2, _ = vote_signature.rsplit('\n', 5)

    (m00, m01, m02, m03, m04, m05, m06, m07, m08, m09,
        m10, m11, m12, m13, m14, m15, m16) = message.split('\n', 16)

    m00 = 'corrupted part' + m00

    corrupted_message = '\n'.join((m00, m01, m02, m03, m04, m05, m06, m07,\
        m08, m09, m10, m11, m12, m13, m14, m15, m16))

    corrupted_signature = corrupted_message
    corrupted_signature += '\n-----------------\n'
    corrupted_signature += '%s\n%s\n%s\n' % (exponent, c_1, c_2)

    return corrupted_signature

def corrupt_implicit_signature(vote_signature, private_key, system):
    """
    Corrupts vote signature by altering the inscribed message (awaited structure
    preserved), so that InvalidSignatureError gets raised upon validation
    """
    message, _, exponent, c_1, c_2, _ = vote_signature.rsplit('\n', 5)

    (m00, m01, m02, m03, m04, m05, m06, m07, m08, m09,
        m10, m11, m12, m13, m14, m15, m16) = message.split('\n', 16)

    V_FINGERPRINT, fingerprint = m01[:13], m01[13:]
    corrupted_fingerprint = fingerprint + 'corrupted part'

    m01 = '%s%s' % (V_FINGERPRINT, corrupted_fingerprint)

    corrupted_message = '\n'.join((m00, m01, m02, m03, m04, m05, m06, m07,\
        m08, m09, m10, m11, m12, m13, m14, m15, m16))

    corrupted_signature = corrupted_message
    corrupted_signature += '\n-----------------\n'
    corrupted_signature += '%s\n%s\n%s\n' % (exponent, c_1, c_2)

    return corrupted_signature


if __name__=='__main__':

    voters = make_voters(10)
    choices = [
        'Party-A: 0-2, 0',
        'Party-A: Candidate-0000',
        'Party-B: generator0-2, 1',
        'Party-B:l Candidate-0001'
        'Party-C:l Candidate-0x00'
    ]

    system = ModPrimeCrypto(_4096_PRIME, _4096_PRIMITIVE)

    # Election key generation and validation
    zeus_keypair = system.create_zeus_keypair()
    zeus_private_key, zeus_public_key = system._extract_keypair(zeus_keypair)
    trustees = system.generate_trustees(7)
    election_key = system.compute_election_key(trustees, zeus_keypair)

    valid = system.validate_election_key(election_key, trustees, zeus_keypair)
    if valid:
        print(' + Election key successfully validated')
    else:
        print(' - Valid election key failed to be validated')

    corrupted_zeus_keypair = system.create_zeus_keypair()
    corrupted_key_1 = system.compute_election_key(trustees, corrupted_zeus_keypair)
    invalid_1 = system.validate_election_key(corrupted_key_1, trustees, zeus_keypair)
    if not invalid_1:
        print(' + Corrupted zeus successfully detected')
    else:
        print(' - Corrupted zeus failed to be detected')

    corrupted_trustees = trustees[:]
    corrupted_trustees[-1] = make_corrupted_public_key()
    corrupted_key_2 = system.compute_election_key(corrupted_trustees, zeus_keypair)
    invalid_2 = system.validate_election_key(corrupted_key_2, trustees, zeus_keypair)
    if not invalid_2:
        print(' + Corrupted trustee sucessfully detected')
    else:
        print(' - Corrupted trustee failed to be detected'    )

    # Make votes
    votes = []

    for voter in voters[:8]:                        # 8 first votes valid
        vote = make_vote(voter)
        votes.append(vote)

    for voter in voters[-2:]:                       # 2 last votes invalid
        vote = make_vote(voter, invalid=True)
        votes.append(vote)

    # Validate submitted votes
    valid_votes = []
    invalid_votes = []

    for i in range(len(votes)):
        try:
            system.validate_submitted_vote(votes[i])
        except InvalidVoteError:
            if i < 8:
                print(' - Valid vote failed to be validated')
            else:
                print(' + Invalid vote successfully detected')
                invalid_votes.append(vote)
        else:
            if i < 8:
                print(' + Valid vote successfully validated')
                valid_votes.append(vote)
            else:
                print(' - Invalid vote failed to be detected')

    # Sign valid votes
    vote_signatures = []

    for i in range(len(valid_votes)):
        vote = valid_votes[i]

        nr_comments = random_integer(0, 5)
        comments = ['comment_%d_on_vote_%s'
            % (i, vote['fingerprint']) for i in range(nr_comments)]

        if i == 0:
            # Tamper signature by altering proof encryption
            vote_signature = make_corrupted_signature_vote(system, vote,
                    comments, election_key, zeus_keypair, trustees, choices)
        else:
            vote_signature = system.sign_vote(
                vote, comments, election_key, zeus_keypair, trustees, choices)

        vote_signatures.append(vote_signature)

    # Corrupt 2nd and 3rd signature

    signature = vote_signatures[1]
    corrupted = corrupt_signature_structure(signature)
    vote_signatures[1] = corrupted              # will raise InvalidStructureError

    signature = vote_signatures[2]
    corrupted = corrupt_implicit_signature(signature, zeus_private_key, system)
    vote_signatures[2] = corrupted              # will raise InvalidSignatureError


    # Verify vote signatures
    verified_signatures = []
    invalid_signatures = []

    for i in range(len(vote_signatures)):
        signature = vote_signatures[i]

        try:
            system.verify_vote_signature(signature)
        except InvalidEncryptionError:
            if i == 0:
                print(' + Invalid encryption proof successfully detected')
                invalid_signatures.append(signature)
            else:
                print(' - Valid encryption proof erroneously invalidated')
            pass
        except InvalidStructureError:
            if i == 1:
                print(' + Invalid signature structure successfully detected')
                invalid_signatures.append(signature)
            else:
                print(' - Valid signature structure erroneously invalidated')
        except InvalidSignatureError:
            if i == 2:
                print(' + Invalid inscribed signature successfully detected')
                invalid_signatures.append(signature)
            else:
                print(' - Valid inscribed signature erroneously invalidated')
            pass
        else:
            if i >= 3:
                print(' + Vote signature successfully verified')
                verified_signatures.append(signature)
            else:
                print(' - Invalid vote signature failed to be detected')
