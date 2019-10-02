import pytest
from copy import deepcopy

from .utils import mk_election, run_until_voting_stage
from ..constants import VOTER_SLOT_CEIL
from ..exceptions import Abortion

election = mk_election()
# trustees = ...


# Run election and test current stage

voting = run_until_voting_stage(election)
def test_current_stage():
    assert election._get_current_stage() is voting


# Run stage and check for updates

# def test_stage_finalization():
#     assert all([
#           ...
#     ])
#     creating.run()
#     assert all([
#           ...
#     ])


# Zeus keypair creation

from tests.helpers import mk_random_vote
def test_main():
    # voters = election.get_voters()
    # audit_codes = election.get_audit_codes()
    # # print(audit_codes)
    # votes = []
    # print()
    # for voter_key in voters.keys():
    #     voter = voters[voter_key]
    #     voter_codes = audit_codes[voter_key]
    #     print(voter_key, voter)
    #     print(voter_key, voter_codes)
    #     print()
    #     vote, _, _, _ = mk_random_vote(election, voter_key=voter_key, audit_code=voter_codes[0])
    #     # votes.append(votes)
    # print()
    assert True
    # assert False
