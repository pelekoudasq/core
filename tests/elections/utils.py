import json
from math import ceil
from copy import deepcopy
# from tests.elections.server import ZeusTestElection
from zeus_core.elections import ZeusCoreElection
from zeus_core.elections.stages import Uninitialized
from tests.elections.sample_configs import config_1

class ZeusTestElection(ZeusCoreElection):
    """
    Provides the most minimal concrete implementation of the
    ZeusCoreElection abstract class for testing purposes
    """
    def load_submitted_votes(self):
        """
        """
        clients = mk_clients(self)
        votes, audit_requests, audit_votes = mk_votes_from_clients(clients)
        submitted_votes = iter(audit_requests + votes + audit_votes)
        while 1:
            try:
                vote = next(submitted_votes)
            except StopIteration:
                break
            yield vote

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
    if 'audit_code' not in vote:
        vote['audit_code'] = None
    voter_secret = vote.get('voter_secret')
    vote['voter_secret'] = cast_exponent(voter_secret) \
        if voter_secret else None
    return vote

from tests.elections.client import Client   # Put here to avoid circular import error

# Election and election contect emulation

def mk_election(election_cls=ZeusTestElection, config=config_1,
        candidates=None, dupl_candidates=False,
        nr_voters=19, dupl_voters=False):
    """
    Emulates election over the provided config after complementing the latter
    with voters and candidates. Provides failure options for testing.
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
    return election_cls(config)


def mk_voting_setup(config=config_1, candidates=None, dupl_candidates=False,
        nr_voters=19, dupl_voters=False, with_votes=False):
    """
    Emulates the situation exactly before casting votes (electoral body
    and submitted votes) with failure options for testing
    """
    election = mk_election(ZeusTestElection, config,
        candidates, dupl_candidates, nr_voters, dupl_voters)
    run_until_voting_stage(election)
    config_crypto = config['crypto']
    election_key = election.get_election_key()
    nr_candidates = len(election.get_candidates())
    voter_keys = election.get_voters()
    clients = mk_clients(election)
    if with_votes:
        votes, audit_requests, audit_votes = mk_votes_from_clients(clients)
        return election, clients, votes, audit_requests, audit_votes
    return election, clients


def mk_clients(election):
    """
    Emulates the electoral body (one client for each stored voter key)
    """
    config_crypto = election.config['crypto']
    voter_keys = election.get_voters()
    nr_candidates = len(election.get_candidates())
    clients = []
    election_key = election.get_election_key()
    for voter_key in voter_keys:
        audit_codes = election.get_voter_audit_codes(voter_key)
        client = Client(config_crypto, election_key, nr_candidates,
            voter_key, audit_codes)
        clients.append(client)
    return clients


def mk_votes_from_clients(clients):
    """
    Emulates votes submitted by the totality of the electoral body:
    about half of them will be genuine votes the rest half will be
    audit-requests (accompanied by corresponding audit publications)
    """
    votes = []
    audit_requests = []
    audit_votes = []
    nr_clients = len(clients)
    for count, client in enumerate(clients):
        voter_key = client.voter_key
        audit_codes = client.audit_codes
        if count < ceil(nr_clients / 2):
            vote = client.mk_genuine_vote()
            votes.append(vote)
        else:
            audit_vote = client.mk_audit_vote()
            audit_votes.append(audit_vote)
            audit_request = deepcopy(audit_vote)
            del audit_request['voter_secret']
            audit_requests.append(audit_request)
    return votes, audit_requests, audit_votes


# Running until stage

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

def run_until_finished_stage(election):
    """
    Runs the provided election until stage finished
    """
    decrypting = run_until_decrypting_stage(election)
    decrypting.run()
    finished = decrypting.next()
    return finished


# JSON utils

def display_json(entity, length=16, trimmed=True):
    """
    Displays JSON object (trims long values by default)
    """
    to_display = trim_json(entity, length=length) \
        if trimmed else entity
    print(json.dumps(to_display, sort_keys=False, indent=4))


def trim_json(entity, length=16):
    """
    Returns a "copy" of the provided JSON with trimmed values for nice display
    """
    def trim_value(value, length=16):
        if type(value) is int:
            return int(f'{value}'[:length])
        elif type(value) is str:
            return f'{value}'[:length]
        elif type(value) is None:
            return ''
            
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
