"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep
from copy import deepcopy

from utils import random_integer
from crypto.exceptions import (InvalidVoteError, InvalidSignatureError)

from tests.constants import _2048_SYSTEM, _4096_SYSTEM, MESSAGE

def _exit(message, code=1):
    print(message)
    print('\nVoting session incomplete: CHECK FAILED\n')
    sys.exit(code)

if __name__=='__main__':

    print('\n------------------- Primitives Test Session -------------------')
    sleep(.5)

    system = _4096_SYSTEM
    # import json
    # print('-- CRYPTOSYSTEM --\n%s'
    #     % json.dumps(system.parameters(), indent=4, sort_keys=True))

    print('\nKey generation')
    sleep(.5)

    keypair = system.keygen()
    private_key, public_key = system._extract_keypair(keypair)
#
    # print('\n-- PUBLIC KEY --\n%d\n' % system.get_value(public_key))

    print('Key validations\n')

    validated = system.validate_public_key(public_key)
    if validated:
        print(' + Valid key sucessfully validated')
    else:
        _exit(' - Valid key erroneously invalidated')

    corrupt_key = deepcopy(public_key)
    corrupt_key['proof']['challenge'] += 100
    validated = system.validate_public_key(corrupt_key)
    if not validated:
        print(' + Invalid key successfully detected')
    else:
        _exit(' - Invalid key failed to be detected')

    print('\nText-message signatures\n')
    sleep(.5)

    message = MESSAGE

    # Valid case
    signed_message = system.sign_text_message(message, private_key)
    verified = system.verify_text_signature(signed_message, public_key)
    if verified:
        print(' + Valid signature sucessfully verified')
    else:
        _exit(' - Valid signature erroneously invalidated')

    # Authentication check
    wrong_secret = private_key + 1
    signed_message = system.sign_text_message(message, wrong_secret)
    verified = system.verify_text_signature(signed_message, public_key)
    if not verified:
        print(' + Unauthorized signer successfully detected')
    else:
        _exit(' - Unauthorized signer failed to be detected')

    # Integrity check
    signed_message = system.sign_text_message(message, private_key)
    signed_message['message'] += '__corrupt_part'
    verified = system.verify_text_signature(signed_message, public_key)
    if not verified:
        print(' + Tampered message successfully detected')
    else:
        _exit(' - Tampered message failed to be detected')

    print('\nPrimitives session complete: ALL CHECKS PASSED\n')
    sys.exit(0)
