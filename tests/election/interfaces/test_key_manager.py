import pytest
from copy import deepcopy

from zeus_core.election.interfaces.key_manager import KeyManager

from tests.constants import (MESSAGE, RES11_SYSTEM, RES11_SECRET, RES11_PUBLIC,
        _2048_SYSTEM, _2048_SECRET, _2048_PUBLIC,
        _4096_SYSTEM, _4096_SECRET, _4096_PUBLIC)


class DummyKeyManager(KeyManager):
    """
    A most minimal impementation of KeyManager for testing purposes
    """
    def __init__(self, cryptosys):
        self.cryptosys = cryptosys

    def get_cryptosys(self):
        return self.cryptosys


# Key generation

@pytest.mark.parametrize('system', [_2048_SYSTEM, _4096_SYSTEM,])
def test_keygen_with_random_private(system):
    key_manager = DummyKeyManager(system)
    keypair = key_manager.keygen()
    _, public_key = key_manager.extract_keypair(keypair)
    public_key, proof = key_manager.extract_public_key(public_key)

    assert system._schnorr_verify(proof, public_key)


__system__secret__public = [
    (_2048_SYSTEM, _2048_SECRET, _2048_PUBLIC),
    (_4096_SYSTEM, _4096_SECRET, _4096_PUBLIC),
]

@pytest.mark.parametrize('system, secret, public', __system__secret__public)
def test_keygen_with_non_random_private(system, secret, public):
    key_manager = DummyKeyManager(system)
    keypair = key_manager.keygen(secret)
    _, public_key = key_manager.extract_keypair(keypair)
    public_key, proof = key_manager.extract_public_key(public_key)

    valid = system._schnorr_verify(proof, public_key)
    assert secret == keypair['private'] and \
           public_key.value == public and \
           valid


# Key validation

__key_manager__public_key__result = []

for system in (
    _2048_SYSTEM,
    _4096_SYSTEM
):
    key_manager = DummyKeyManager(system)
    public_key = key_manager.keygen()['public']

    # Non-corrupt case
    __key_manager__public_key__result.append((key_manager, public_key, True))

    # Corrupt key value
    corrupt_value = public_key['value'].clone()
    corrupt_value.reduce_value()
    corrupt_public_key = {
        'value': corrupt_value,
        'proof': public_key['proof']
    }
    __key_manager__public_key__result.append(
        (key_manager, corrupt_public_key, False))

    # Corrupt key proof
    corrupt_proof = deepcopy(public_key['proof'])
    corrupt_proof['challenge'] += 100
    corrupt_public_key = {
        'value': public_key['value'],
        'proof': corrupt_proof
    }
    __key_manager__public_key__result.append(
        (key_manager, corrupt_public_key, False))

@pytest.mark.parametrize('key_manager, public_key, result',
    __key_manager__public_key__result)
def test_validate_public_key(key_manager, public_key, result):
    assert key_manager.validate_public_key(public_key) is result
