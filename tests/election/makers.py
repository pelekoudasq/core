"""
"""
from copy import deepcopy
from .emulators import ZeusTestElection
from .emulators.election_configs import config_1


def mk_election(election_cls=ZeusTestElection, config=config_1,
                dupl_candidates=False, dupl_voters=False, **kwargs):
    """
    Emulates election over the provided config after complementing the latter
    with voters and candidates. Offers failure options for testing.
    """
    election = election_cls(deepcopy(config), **kwargs)
    nr_candidates = election.get_nr_candidates()
    if nr_candidates >= 2 and dupl_candidates:
        candidates = self.get_candidates()
        candidates[1] = candidates[0]
    nr_voters = election.get_nr_voters()
    if nr_voters >= 2 and dupl_voters:
        voters = self.get_voters()
        voters[1] = voters[0]
    return election


def mk_voting_setup(election_cls=ZeusTestElection, config=config_1,
                    dupl_candidates=False, dupl_voters=False,
                    with_votes=False):
    """
    Emulates the situation exactly before casting votes (electoral body
    and submitted votes) with failure options for testing
    """
    election = mk_election(election_cls, config, dupl_candidates, dupl_voters)
    election.run_until_voting_stage()
    if with_votes:
        votes, audit_requests, audit_votes = election.mk_votes_from_voters()
        return election, votes, audit_requests, audit_votes
    return election
