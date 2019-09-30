import pytest
from copy import deepcopy

from tests.constants import _2048_SYSTEM, _2048_SECRET
from .utils import _2048_zeus_election, run_until_creating_stage
from ..exceptions import Abortion

election = _2048_zeus_election
creating = run_until_creating_stage(election)

def test_Abortion():
    assert True


# Zeus keypair creation

def test_create_zeus_keypair_Abortion():
    with pytest.raises(Abortion):
        creating.create_zeus_keypair(1)

def test_create_zeus_keypair():
    cryptosys = election.get_cryptosys()
    keypair_1 = creating.create_zeus_keypair(_2048_SECRET)
    keypair_2 = _2048_SYSTEM.keygen(_2048_SECRET)
    assert cryptosys._get_public_value(keypair_1) == \
        _2048_SYSTEM._get_public_value(keypair_2)


# Trustees validation

def test_validate_trustees_Abortion():
    trustees = deepcopy(election.config['trustees'])
    trustees[0]['value'] += 1   # Corrupt first trustee
    with pytest.raises(Abortion):
        creating.validate_trustees(trustees)

def test_validate_trustees():
    trustees = election.config['trustees']
    validated_trustees = creating.validate_trustees(trustees)
    assert validated_trustees == creating.deserialize_trustees(trustees)


# Candidates creation

candidates = election.config['candidates']

__abort_cases = [deepcopy(candidates) for _ in range(3)]
__abort_cases[0][1] = __abort_cases[0][2]   # Duplicate name
__abort_cases[1][1] += '%'                  # Append unacceptable character
__abort_cases[2][1] += '\n'                 # Append unacceptable character
@pytest.mark.parametrize('candidates', __abort_cases)
def test_create_candidates_Abortion(candidates):
    with pytest.raises(Abortion):
        creating.create_candidates(candidates)

def test_create_candidates():
    assert candidates == creating.create_candidates(candidates)


# Voters and audit codes creation

def test_create_voters_and_audit_codes():
    assert True
