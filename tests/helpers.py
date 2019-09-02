from crypto.modprime import ModPrimeElement
from crypto.constants import (V_FINGERPRINT, V_PREVIOUS, V_ELECTION,
    V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS, V_GENERATOR,
    V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE, V_RESPONSE,
    V_COMMENTS, V_INDEX, V_CAST_VOTE, V_AUDIT_REQUEST, V_PUBLIC_AUDIT,
    V_PUBLIC_AUDIT_FAILED)
from utils import random_integer

VOTER_KEY_CEIL = 2 ** 256
PLAINTEXT_CEIL = 2 ** 512

def make_voters(nr_voters):
    return ['%x' % random_integer(2, VOTER_KEY_CEIL) for _ in range(nr_voters)]

def make_corrupted_public_key(system):
    corrupted_keypair = system.keygen()
    return system._extract_public(corrupted_keypair)

def make_vote(voter, system, election_key, invalid=False):
    plaintext = random_integer(2, PLAINTEXT_CEIL)
    vote = system.vote(election_key, voter, plaintext)
    if invalid:
        vote['fingerprint'] = vote['fingerprint'] + '__corrupted_part'
    return vote

def make_corrupted_signature_vote(system, vote, comments, election_key,
                            zeus_keypair, trustees, choices):
    """
    Creates a corrupted vote signature, such that InvalidEncryptionError
    gets raised upon validation.
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

def _make_ciphers(mixnet, nr_ciphers=12):
    random_element = mixnet.cryptosystem.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

def _make_ciphers_to_mix(mixnet, election_key, nr_ciphers=12):
    params = mixnet.cryptosystem.parameters()
    ciphers_to_mix = {
        'modulus': params['modulus'],
        'order': params['order'],
        'generator': params['generator'],
        'public': election_key,
        'original_ciphers': [],
        'mixed_ciphers': _make_ciphers(mixnet, nr_ciphers),
        'cipher_collections': []
    }
    return ciphers_to_mix
