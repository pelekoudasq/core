import pytest
from copy import deepcopy

from tests.constants import _2048_SYSTEM
from crypto.constants import _2048_PRIME, _2048_ORDER, _2048_GENERATOR
from .utils import _2048_zeus_election, run_until_uninitialized_stage
from ..exceptions import Abortion

election = _2048_zeus_election
uninitialized = run_until_uninitialized_stage(election)

def test_Abortion():
    assert True


# Cryptosystem initialization

crypto_cls = election.config['crypto']['cls']
crypto_config = election.config['crypto']['config']

__abort_cases = [[crypto_cls, deepcopy(crypto_config)] for _ in range(2)]
__abort_cases[0][1]['modulus'] += 1
__abort_cases[1][1]['modulus'] = 7
@pytest.mark.parametrize('crypto_cls, crypto_config', __abort_cases)
def test_init_cryptosys_Abortion(crypto_cls, crypto_config):
    with pytest.raises(Abortion):
        uninitialized.init_cryptosys(crypto_cls, crypto_config)

def test_init_cryptosys():
    cryptosys = uninitialized.init_cryptosys(crypto_cls, crypto_config)
    assert _2048_SYSTEM.parameters() == cryptosys.parameters()

# Mixnet intiialization

cryptosys = election.get_cryptosys()

mixnet_cls = election.config['mixnet']['cls']
mixnet_config = election.config['mixnet']['config']

__abort_cases = [[mixnet_cls, deepcopy(mixnet_config)] for _ in range(2)]
class PseudoCrypto(object):
    def update(self, *args): pass
__abort_cases[0][0] = PseudoCrypto()
__abort_cases[1][1] = {}
@pytest.mark.parametrize('mixnet_cls, mixnet_config', __abort_cases)
def test_init_mixnet_Abortion(mixnet_cls, mixnet_config):
    with pytest.raises(Abortion):
        uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)

def test_init_mixnet():
    mixnet = uninitialized.init_mixnet(mixnet_cls, mixnet_config, cryptosys)
    assert mixnet.__dict__ == {
        '_Zeus_sk__modulus': _2048_PRIME,
        '_Zeus_sk__order': _2048_ORDER,
        '_Zeus_sk__generator': _2048_GENERATOR,
    }
