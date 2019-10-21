"""
Tests the interfaces for vote signing and vote-signature verification
"""

import pytest
import json
from zeus_core.elections.exceptions import InvalidVoteSignature
from zeus_core.elections.signatures import Signer, Verifier
from zeus_core.elections.constants import (V_CAST_VOTE, V_PUBLIC_AUDIT,
    V_PUBLIC_AUDIT_FAILED, V_AUDIT_REQUEST, V_FINGERPRINT, V_INDEX, V_PREVIOUS,
    V_VOTER, V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS,
    V_GENERATOR, V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE,
    V_RESPONSE, V_COMMENTS, V_SEPARATOR, NONE, VOTER_KEY_CEIL)
from zeus_core.elections.utils import extract_vote
from zeus_core.utils import random_integer
from tests.elections.utils import (display_json, mk_voting_setup, adapt_vote)

def textify_vote(signer, vote, comments, corrupt_trustees=False,
        corrupt_candidates=False, malformed=False):
    """
    Simulates the Signer.textify_vote() with failure options for testing
    """
    election = signer.election
    cryptosys = signer.cryptosys

    hex_zeus_public_key = election.get_hex_zeus_public_key()
    hex_trustee_keys = election.get_hex_trustee_keys()[:]
    candidates = election.get_candidates()[:]

    (vote_crypto, vote_election_key, _, encrypted_ballot, fingerprint,
        _, _, previous, index, status, _) = extract_vote(vote)

    hex_crypto_params = cryptosys.hexify_crypto(vote_crypto)    # possibly corrupted
    hex_election_key = '%x' % vote_election_key                 # possibly corrupted

    alpha, beta, commitment, challenge, response = \
        cryptosys.hexify_encrypted_ballot(encrypted_ballot)

    # Further corruptions
    if corrupt_trustees:
        del hex_trustee_keys[-1]
    if corrupt_candidates:
        del candidates[-1]

    t00 = status if status is not None else NONE
    if malformed:
        t00 = 'MALFORMED... ' + t00
    t01 = V_FINGERPRINT + fingerprint
    t02 = V_INDEX + f'{index if index is not None else NONE}'
    t03 = V_PREVIOUS + f'{previous if previous is not None else NONE}'
    t04 = V_ELECTION + hex_election_key
    t05 = V_ZEUS_PUBLIC + hex_zeus_public_key
    t06 = V_TRUSTEES + ' '.join(hex_trustee_keys)
    t07 = V_CANDIDATES + ' % '.join(candidates)
    t08, t09, t10 = hex_crypto_params
    t11 = V_ALPHA + alpha
    t12 = V_BETA + beta
    t13 = V_COMMITMENT + commitment
    t14 = V_CHALLENGE + challenge
    t15 = V_RESPONSE + response
    t16 = V_COMMENTS + f'{comments}'

    textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
        t09, t10, t11, t12, t13, t14, t15, t16))

    return textified


def mk_vote_signature(signer, vote, comments=None, corrupt_crypto=False,
        corrupt_public=False, corrupt_trustees=False,
        corrupt_candidates=False, malformed=False,
        corrupt_proof=False):
    """
    Simulates the Signer.sign() method with failure options for testing
    """
    if corrupt_crypto:
        keys = iter(vote['crypto'])
        key_1, key_2 = next(keys), next(keys)
        value_2 = vote['crypto'][key_2]
        vote['crypto'][key_2] = vote['crypto'][key_1]
        vote['crypto'][key_1] = value_2
    if corrupt_public:
        vote['public'] += 1
    if corrupt_proof:
        proof = vote['encrypted_ballot']['proof']
        challenge = proof['challenge']
        response = proof['response']
        proof['challenge'] = response
        proof['response'] = challenge
    textified_vote = textify_vote(signer, vote, comments,
        corrupt_trustees=corrupt_trustees,
        corrupt_candidates=corrupt_candidates,
        malformed=malformed)
    election = signer.election
    cryptpsys = signer.cryptosys
    zeus_private_key = election.get_zeus_private_key()
    signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
    _, signature = cryptosys.extract_signed_message(signed_vote)
    vote_signature = signer.format_vote_signature(textified_vote, signature)
    return vote_signature


if __name__ == '__main__':
    election, clients = mk_voting_setup()
    cryptosys = election.get_cryptosys()
    signer = Signer(election)
    verifier = Verifier(election)

    client = clients[0]

    mk_genuine_vote = client.mk_genuine_vote
    mk_audit_request = client.mk_audit_request
    mk_audit_vote = client.mk_audit_vote
    for label, mk_vote in (
        ('Vote:', mk_genuine_vote),
        ('Audit-request:', mk_audit_request),
        ('Audit-vote:', mk_audit_vote),
    ):
        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = signer.sign_vote(vote, ['some comment...,'])
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[-] {label} Valid signature erroneously not verified')
        else:
            print(f'[+] {label} Signature successfully verified')

        vote = mk_vote()
        adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, malformed=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Malformed vote signature successfully detected')
        else:
            print(f'[-] {label} Malformed vote signature failed to be detected')

        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, corrupt_crypto=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Election mismatch (crypto discord) successfully detected')
        else:
            print(f'[-] {label} Election mismatch (crypto discord) failed to be detected')

        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, corrupt_public=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Election mismatch (key discord) successfully detected')
        else:
            print(f'[-] {label} Election mismatch (key discord) failed to be detected')

        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, corrupt_trustees=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Election mismatch (trustees discord) successfully detected')
        else:
            print(f'[-] {label} Election mismatch (trustees discord) failed to be detected')

        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, corrupt_candidates=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Election mismatch (candidates discord) successfully detected')
        else:
            print(f'[-] {label} Election mismatch (candidates discord) failed to be detected')

        vote = mk_vote()
        vote = adapt_vote(cryptosys, vote)
        vote_signature = mk_vote_signature(signer, vote, corrupt_proof=True)
        try:
            verifier.verify_vote_signature(vote_signature)
        except InvalidVoteSignature:
            print(f'[+] {label} Invalid encryption successfully detected')
        else:
            print(f'[-] {label} Invalid encryption failed to be detected')
