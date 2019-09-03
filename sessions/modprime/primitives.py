"""
Exits with 1 if any of the checks fails; othewise terminates with 0 (only pluses)
"""
import sys
from time import sleep
from copy import deepcopy
from gmpy2 import mpz

from utils import random_integer
from crypto.modprime import ModPrimeElement
from crypto.exceptions import (InvalidVoteError, InvalidSignatureError)

from tests.constants import (_2048_SYSTEM, _2048_KEY, _2048_DDH, _4096_SYSTEM,
    _4096_KEY, _4096_DDH, MESSAGE)

def _exit(message, code=1):
    print(message)
    print('\nVoting session incomplete: CHECK FAILED\n')
    sys.exit(code)

if __name__=='__main__':

    print('\n------------------- Primitives Test Session -------------------')
    sleep(.5)

    system = _4096_SYSTEM
    secret = _4096_KEY
    DDH    = _4096_DDH
    # import json
    # print('-- CRYPTOSYSTEM --\n%s'
    #     % json.dumps(system.parameters(), indent=4, sort_keys=True))

    print('\nSchnorr protocol\n')
    sleep(.5)

    secret = mpz(secret)
    public = system.group.generate(secret)
    extras = [0, 7, 11, 666]

    # Valid case
    proof = system._schnorr_proof(secret, public, *extras)
    verified = system._schnorr_verify(proof, public, *extras)
    if verified:
        print(' + Valid proof successfully verified')
    else:
        _exit(' - Valid proof erroneously invalidated')

    # Corrupt logarithm
    corrupt_secret = secret + 1
    corrupt_proof = system._schnorr_proof(corrupt_secret, public, *extras)
    verified = system._schnorr_verify(corrupt_proof, public, *extras)
    if not verified:
        print(' + Invalid proof (wrong logarithm) successfully detected')
    else:
        _exit(' - Wrong logarithm failed to be detected')

    # Corrupt extras
    corrupt_extras = deepcopy(extras)
    corrupt_extras[0] += 1
    verified = system._schnorr_verify(proof, public, *corrupt_extras)
    if not verified:
        print(' + Invalid proof (wrong extras) successfully detected')
    else:
        _exit(' - Wrong extras failed to be detected')

    # Corrupt proof by tampering commitment
    corrupt_proof = deepcopy(proof)
    corrupt_proof['commitment'].reduce_value()
    verified = system._schnorr_verify(corrupt_proof, public, *corrupt_extras)
    if not verified:
        print(' + Invalid proof (tampered commitment) successfully detected')
    else:
        _exit(' - Tampered commitment failed to be detected')

    # Corrupt proof by tampering challenge
    corrupt_proof = deepcopy(proof)
    corrupt_proof['challenge'] += 1
    verified = system._schnorr_verify(corrupt_proof, public, *corrupt_extras)
    if not verified:
        print(' + Invalid proof (tampered challenge) successfully detected')
    else:
        _exit(' - Tampered chalenge failed to be detected')

    # Corrupt proof by tampering response
    corrupt_proof = deepcopy(proof)
    corrupt_proof['response'] += 1
    verified = system._schnorr_verify(corrupt_proof, public, *corrupt_extras)
    if not verified:
        print(' + Invalid proof (tampered response) successfully detected')
    else:
        _exit(' - Tampered response failed to be detected')

    print('\nChaum-Pedersen protocol\n')
    sleep(.5)

    modulus = system.group.modulus

    # Valid case
    ddh = [ModPrimeElement(elem, modulus) for elem in DDH['ddh']]
    z = mpz(DDH['log'])
    proof = system._chaum_pedersen_proof(ddh, z)
    valid = system._chaum_pedersen_verify(ddh, proof)
    if valid:
        print(' + Valid proof successfully verified')
    else:
        print(' - Invalid proof erroneously invalidated')

    # Corrupt first member
    corrupt = ddh[0].clone()
    corrupt.reduce_value()
    corrupt_ddh = [corrupt, ddh[1], ddh[2]]
    proof = system._chaum_pedersen_proof(corrupt_ddh, z)
    valid = system._chaum_pedersen_verify(corrupt_ddh, proof)
    if not valid:
        print(' + Invalid tuple successfully detected')
    else:
        print(' - Invalid tuple failed to be detected')

    # Corrupt second member
    corrupt = ddh[1].clone()
    corrupt.reduce_value()
    corrupt_ddh = [ddh[0], corrupt, ddh[2]]
    proof = system._chaum_pedersen_proof(corrupt_ddh, z)
    valid = system._chaum_pedersen_verify(corrupt_ddh, proof)
    if not valid:
        print(' + Invalid tuple successfully detected')
    else:
        print(' - Invalid tuple failed to be detected')

    # Corrupt third member
    corrupt = ddh[2].clone()
    corrupt.reduce_value()
    corrupt_ddh = [ddh[0], ddh[1], corrupt]
    proof = system._chaum_pedersen_proof(corrupt_ddh, z)
    valid = system._chaum_pedersen_verify(corrupt_ddh, proof)
    if not valid:
        print(' + Invalid tuple successfully detected')
    else:
        print(' - Invalid tuple failed to be detected')

    # Corrupt logarithm
    proof = system._chaum_pedersen_proof(ddh, z + 1)
    valid = system._chaum_pedersen_verify(ddh, proof)
    if not valid:
        print(' + Invalid logarithm successfully detected')
    else:
        print(' - Invalid logarithm failed to be detected')

    print('\nKey validations\n')
    sleep(.5)

    keypair = system.keygen()
    private_key, public_key = system._extract_keypair(keypair)
    # print('\n-- PUBLIC KEY --\n%d\n' % system.get_value(public_key))

    validated = system.validate_public_key(public_key)
    if validated:
        print(' + Key sucessfully validated')
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
