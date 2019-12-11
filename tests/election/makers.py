"""
"""
from copy import deepcopy
from .emulators import ZeusTestElection
from .emulators.election_configs import config_1


def mk_election(election_cls=ZeusTestElection, config=config_1, **kwargs):
    """
    """
    election = election_cls(deepcopy(config), **kwargs)
    return election


def mk_voting_setup(election_cls=ZeusTestElection, config=config_1,
                    with_votes=False):
    """
    Emulates the situation exactly before casting votes (electoral body
    and submitted votes)
    """
    election = mk_election(election_cls, config)
    election.run_until_voting_stage()
    if with_votes:
        votes, audit_requests, audit_votes = election.mk_votes_from_voters()
        return election, votes, audit_requests, audit_votes
    return election
