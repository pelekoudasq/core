"""
"""
import json
from .emulators import ZeusTestElection
from .emulators.config_samples import config_1


candidates_default = 'tests/election/emulators/candidates.json'

def mk_election(election_cls=ZeusTestElection, config=config_1,
                candidates_file=None, dupl_candidates=False,
                nr_voters=19, dupl_voters=False, **kwargs):
    """
    Emulates election over the provided config after complementing the latter
    with voters and candidates. Offers failure options for testing.
    """
    if candidates_file is None:
        candidates_file = candidates_default
    with open(candidates_file) as __file:
        candidates = json.load(__file)
    if len(candidates) >= 2 and dupl_candidates:
        candidates[1] = candidates[0]
    voters = [(f'-{str(i).zfill(8)}', 1) for i in range(nr_voters)]
    print(voters)
    if nr_voters >= 2 and dupl_voters:
        voters[1] = voters[0]
    config.update({'candidates': candidates, 'voters': voters})
    return election_cls(config, **kwargs)


def mk_voting_setup(election_cls=ZeusTestElection, config=config_1,
                    candidates_file=None, dupl_candidates=False,
                    nr_voters=19, dupl_voters=False, with_votes=False):
    """
    Emulates the situation exactly before casting votes (electoral body
    and submitted votes) with failure options for testing
    """
    election = mk_election(ZeusTestElection, config, candidates_file,
                           dupl_candidates, nr_voters, dupl_voters)
    election.run_until_voting_stage()
    election.mk_voter_clients()
    if with_votes:
        votes, audit_requests, audit_votes = election.mk_votes_from_voters()
        return election, votes, audit_requests, audit_votes
    return election
