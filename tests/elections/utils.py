import json
from zeus_core.elections.elections import ZeusCoreElection
from zeus_core.elections.stages import Uninitialized
from tests.elections.sample_configs import config_1

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

def mk_election(config=config_1, candidates=None, dupl_candidates=False,
        nr_voters=19, dupl_voters=False):
    """
    Returns an election object over the provided config after
    complementing the latter with voters and candidates
    """
    if candidates is None:
        candidates = [
            'Party-A: 0-2, 0',
            'Party-A: Candidate-0000',
            'Party-A: Candidate-0001',
            'Party-A: Candidate-0002',
            'Party-A: Candidate-0003',
            'Party-B: 0-2, 1',
            'Party-B: Candidate-0000',
            'Party-B: Candidate-0001',
            'Party-B: Candidate-0002',
        ]
    if len(candidates) >= 2 and dupl_candidates:
        candidates[1] = candidates[0]

    voters = [(f'Voter-{str(i).zfill(8)}', 1) for i in range(nr_voters)]
    if nr_voters >= 2 and dupl_voters:
        voters[1] = voters[0]

    config.update({'candidates': candidates, 'voters': voters})
    return ZeusCoreElection(config=config)


from tests.elections.client import Client

def mk_voting_setup(config=config_1, candidates=None, dupl_candidates=False,
        nr_voters=19, dupl_voters=False):
    """
    Mocks voting stage setup: runs election over the provided configs until
    voting stage; returns the election along with voters (clients) and votes.
    The first half of votes will be genuine votes, the third and last
    quarters will be audit-requests and audit-votes respectively
    """
    election = mk_election(config, candidates, dupl_candidates, nr_voters, dupl_voters)
    run_until_voting_stage(election)
    config_crypto = config['crypto']
    election_key = election.get_election_key()
    voter_keys = election.get_voters()
    clients = []
    votes = []
    nr_candidates = len(election.get_candidates())
    for count, voter_key in enumerate(voter_keys):
        audit_codes = election.get_voter_audit_codes(voter_key)
        client = Client(config_crypto, election_key, nr_candidates,
            voter_key, audit_codes)
        vote = client.mk_genuine_vote()
        clients.append(client)
        votes.append(vote)
    return election, clients, votes
