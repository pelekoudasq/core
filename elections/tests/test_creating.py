import pytest
from copy import deepcopy

from tests.constants import _2048_SYSTEM, _2048_SECRET
from .utils import mk_election, run_until_creating_stage
from ..constants import VOTER_SLOT_CEIL
from ..exceptions import Abortion

election = mk_election()
trustees = election.config['trustees']
candidates = election.config['candidates']
voters = election.config['voters']


# Run election and test current stage
creating = run_until_creating_stage(election)
def test_current_stage():
    assert election._get_current_stage() is creating

# Run stage and check for updates
def test_stage_finalization():
    assert all([election.get_zeus_private_key() == None,
                election.get_zeus_public_key() == None,
                election.get_trustees() == {},
                election.get_election_key() == None,
                election.get_candidates() == [],
                election.get_voters() == {},
                election.get_audit_codes() == {},])
    creating.run()
    assert all([election.get_zeus_private_key() != None,
                election.get_zeus_public_key() != None,
                election.get_trustees() != {},
                election.get_election_key() != None,
                election.get_candidates() != [],
                election.get_voters() != {},
                election.get_audit_codes() != {},])


# Test zeus keypair creation

def test_create_zeus_keypair():
    cryptosys = election.get_cryptosys()
    zeus_keypair_1 = creating.create_zeus_keypair(_2048_SECRET)
    zeus_keypair_2 = _2048_SYSTEM.keygen(_2048_SECRET)
    assert cryptosys._get_public_value(zeus_keypair_1) == \
        _2048_SYSTEM._get_public_value(zeus_keypair_2)

def test_create_zeus_keypair_Abortion():
    with pytest.raises(Abortion):
        creating.create_zeus_keypair(1)


# Test trustees validation

def test_validate_trustees():
    validated_trustees = creating.validate_trustees(trustees)
    assert validated_trustees == creating.deserialize_trustees(trustees)

def test_validate_trustees_Abortion():
    corrupt_trustees = deepcopy(trustees)
    corrupt_trustees[0]['value'] += 1
    with pytest.raises(Abortion):
        creating.validate_trustees(corrupt_trustees)


# Test election key computation

def test_compute_election_key():
    election_key_hex = \
    '75142c805b7ba32068e48293d711e78fdbc8ff3bd6c080337d409554bb50287cb73e6eb' + \
    '56924ea287aa7902ecc3169f275e4ccf8cd9ead105f1c3907e81cdf16f7b6d5ab34afb6' + \
    'fdbcd41b4dd6c9172935d8e41a725dac0f308c6ea755d936e258f33127f976a2dcbe7d2' + \
    '5fdc001bae7847bd29b2c0448cc4fae1fba892d327667218836cd30a09a5f903dacab7d' + \
    '323b786898b77d3bc4ba117630749ebb9b8b061b320e67c3d8cd19d9ac34332eb909a49' + \
    '873510414c0fb15e8872c3dfec2ef9bdc5c72e35cdeb6216465967e7f725feefa55ea91' + \
    '86debb96d7aceefc480915f1f569283239efbbe058a72f1dcbfdec33149fcdfaddb5170' + \
    'a7f7ac0d81e51c8'
    zeus_keypair = creating.create_zeus_keypair(_2048_SECRET)
    validated_trustees = creating.validate_trustees(trustees)
    election_key = creating.compute_election_key(validated_trustees, zeus_keypair)
    assert election_key['value'].to_hex() == election_key_hex and \
        election_key['proof'] == None


# Test candidates creation

def test_create_candidates():
    assert candidates == creating.create_candidates(candidates)

__abort_cases = [deepcopy(candidates) for _ in range(3)]
__abort_cases[0][1] = __abort_cases[0][2]
__abort_cases[1][1] += '%'
__abort_cases[2][1] += '\n'

@pytest.mark.parametrize('candidates', __abort_cases)
def test_create_candidates_Abortion(candidates):
    with pytest.raises(Abortion):
        creating.create_candidates(candidates)


# Test voters and audit codes creation

def test_create_voters_and_audit_codes():
    new_voters, audit_codes = creating.create_voters_and_audit_codes(voters)
    inverse_voters = {voter: voter_key
        for voter_key, voter in new_voters.items()}
    get_audit_codes = lambda voter: audit_codes[inverse_voters[voter]]
    assert all(audit_codes[voter_key] == get_audit_codes(new_voters[voter_key])
        for voter_key in new_voters.keys())

__abort_cases = [[deepcopy(voters), VOTER_SLOT_CEIL] for _ in range(3)]
del __abort_cases[0][0][:]                              # Zero number of voters
__abort_cases[1][0][1] = [
    __abort_cases[1][0][0][0],
    __abort_cases[1][0][1][0]]                          # Duplicate voter name
__abort_cases[2][1] = 1                                 # Insufficient slot variation

@pytest.mark.parametrize('voters, voter_slot_ceil', __abort_cases)
def test_create_voters_and_audit_codes_Abortion(voters, voter_slot_ceil):
    with pytest.raises(Abortion):
        creating.create_voters_and_audit_codes(voters, voter_slot_ceil)
