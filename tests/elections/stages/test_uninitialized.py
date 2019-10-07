import pytest
from copy import deepcopy

from tests.constants import _2048_SYSTEM
from crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from .utils import mk_election, run_until_uninitialized_stage
from elections.exceptions import Abortion


election = mk_election()
crypto_cls = election.config['crypto']['cls']
crypto_config = election.config['crypto']['config']
mixnet_cls = election.config['mixnet']['cls']
mixnet_config = election.config['mixnet']['config']


# Run election and test current stage
uninitialized = run_until_uninitialized_stage(election)
def test_current_stage(): 
    assert election._get_current_stage() is uninitialized

# Run stage and check for updates
def test_stage_finalization():
    assert all([
        election.get_cryptosys() == None,
        election.get_crypto_params() == {},
        election.get_mixnet() == None,
    ])
    uninitialized.run()
    assert all([
        election.get_cryptosys() != None,
        election.get_crypto_params() == election.get_cryptosys().parameters(),
        election.get_mixnet() != None,
    ])


# Test cryptosystem initialization

def test_init_cryptosys():
    cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
    assert _2048_SYSTEM.parameters() == cryptosys.parameters()

__abort_cases = [[crypto_cls, deepcopy(crypto_config)] for _ in range(2)]
__abort_cases[0][1]['modulus'] += 1
__abort_cases[1][1]['modulus'] = 7

@pytest.mark.parametrize('crypto_cls, crypto_config', __abort_cases)
def test_init_cryptosys_Abortion(crypto_cls, crypto_config):
    with pytest.raises(Abortion):
        uninitialized.init_cryptosys(crypto_cls, crypto_config)


# Test mixnet intitialization

def test_init_mixnet():
    cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
    mixnet = uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
    assert mixnet.parameters() == {
        'cryptosys': cryptosys,
        'nr_rounds': mixnet_config['nr_rounds'],
        'nr_mixes': mixnet_config['nr_mixes'],
    }

class PseudoMixnet(object):
    def update(self, *args): pass
pseudo_config = {}

__abort_cases = [
    (PseudoMixnet, mixnet_config),
    (mixnet_cls, pseudo_config)
]

@pytest.mark.parametrize('mixnet_cls, mixnet_config', __abort_cases)
def test_init_mixnet_Abortion(mixnet_cls, mixnet_config):
    cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
    with pytest.raises(Abortion):
        uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
