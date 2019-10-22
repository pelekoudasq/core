import json
from zeus_core.elections.elections import ZeusCoreElection
from zeus_core.elections.stages import Uninitialized
from tests.elections.sample_configs import *

def adapt_vote(cryptosys, vote, serialize=True):
    """
    Emulates vote adaptment from the server's side (no checks,
    only key rearrangement and values deserialization)
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

def trim_json(entity, length=16):
    """
    Returns a "copy" of the provided JSON with trimmed values for nice display
    """
    trim_value = lambda value: int(f'{value}'[:length]) \
        if type(value) is not str else f'{value}'[:length]
    if type(entity) is list:
        trimmed = []
        for elem in entity:
            if type(elem) in (list, dict):
                trimmed.append(trim_json(elem))
            else:
                trimmed.append(trim_value(elem))
    elif type(entity) is dict:
        trimmed = {}
        for key, value in entity.items():
            trimmed[key] = trim_value(value) if type(value) is not dict \
                else trim_json(value, length=length)
    return trimmed

def display_json(entity, length=16, trimmed=True):
    """
    Displays JSON object (trims long values by default)
    """
    to_display = trim_json(entity, length=length) \
        if trimmed else entity
    print(json.dumps(to_display, sort_keys=False, indent=4))

def run_until_uninitialized_stage(election):
    """
    Runs the provided election until stage uninitialized
    """
    uninitialized = Uninitialized(election)
    return uninitialized

def run_until_creating_stage(election):
    """
    Runs the provided election until stage creating
    """
    uninitialized = run_until_uninitialized_stage(election)
    uninitialized.run()
    creating = uninitialized.next()
    return creating

def run_until_voting_stage(election):
    """
    Runs the provided election until stage voting
    """
    creating = run_until_creating_stage(election)
    creating.run()
    voting = creating.next()
    return voting

def run_until_mixing_stage(election):
    """
    Runs the provided election until stage mixing
    """
    voting = run_until_voting_stage(election)
    voting.run()
    mixing = voting.next()
    return mixing

def run_until_decrypting_stage(election):
    """
    Runs the provided election until stage decrypting
    """
    mixing = run_until_mixing_stage(election)
    mixing.run()
    decrypting = mixing.next()
    return decrypting

def run_until_finalized_stage(election):
    """
    Runs the provided election until stage finalized
    """
    decrypting = run_until_decrypting_stage(election)
    decrypting.run()
    finalized = decrypting.next()
    return finalized

def mk_election(config=config_1):
    """
    Returns an election object over the provided config
    """
    election = ZeusCoreElection(config=config)
    return election

from tests.elections.client import Client

def mk_voting_setup(config=config_1):
    """
    Setup for voting stage (run election until voting stage
    and return along with voters as clients)
    """
    election = mk_election(config=config)
    run_until_voting_stage(election)
    config_crypto = config['crypto']
    election_key = election.get_election_key()
    voter_keys = election.get_voters()
    clients = []
    nr_candidates = len(election.get_candidates())
    for voter_key in voter_keys:
        audit_codes = election.get_voter_audit_codes(voter_key)
        client = Client(config_crypto, election_key, nr_candidates,
            voter_key, audit_codes)
        clients.append(client)
    return election, clients
