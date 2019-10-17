from zeus_core.elections.elections import ZeusCoreElection
from zeus_core.elections.stages import Uninitialized
from tests.elections.client import Client
from tests.elections.sample_configs import *

def mk_election(config=config_1):
    election = ZeusCoreElection(config=config)
    return election

def run_until_uninitialized_stage(election):
    uninitialized = Uninitialized(election)
    return uninitialized

def run_until_creating_stage(election):
    uninitialized = run_until_uninitialized_stage(election)
    uninitialized.run()
    creating = uninitialized.next()
    return creating

def run_until_voting_stage(election):
    creating = run_until_creating_stage(election)
    creating.run()
    voting = creating.next()
    return voting

def mk_voting_setup(config=config_1):
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
