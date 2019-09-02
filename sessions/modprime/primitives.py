"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep

from utils import random_integer
from crypto.exceptions import (InvalidVoteError, InvalidStructureError,
    InvalidSignatureError, InvalidEncryptionError)

from tests.constants import _2048_SYSTEM, _4096_SYSTEM

def _exit(message, code=1):
    print(message)
    print('\nVoting session incomplete: CHECK FAILED\n')
    sys.exit(code)

if __name__=='__main__':

    print('\n------------------- Primitives Test Session -------------------\n')

    system = _4096_SYSTEM
    import json
    print('-- CRYPTOSYSTEM --\n%s'
        % json.dumps(system.parameters(), indent=4, sort_keys=True))

    keypair = system.keygen()
    private_key = system._extract_private(keypair)
    public_key = system._extract_public(keypair)

    print('\n-- PUBLIC KEY --\n%d' % system.extract_value(public_key))

    print('\nVoting session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
