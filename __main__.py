from crypto import ModPrimeCrypto, ModPrimeElement, _4096_PRIME, _4096_PRIMITIVE
from crypto.utils import random_integer

system = ModPrimeCrypto(modulus=_4096_PRIME, primitive=_4096_PRIMITIVE)
keypair = system.keygen()
private_key, public_key = system._extract_keypair(keypair)

def make_vote():

    VOTER_KEY_CEIL = 2 ** 256
    voter = '%x' % random_integer(2, VOTER_KEY_CEIL)

    value = random_integer(2, system.group.order)
    element = ModPrimeElement(value, system.group.modulus)
    ciphertext, randomness = system._encrypt_with_randomness(element, public_key['value'])
    proof = system._prove_encryption(ciphertext, randomness)
    encrypted = system._set_ciphertext_proof(ciphertext, proof)

    fingerprint = system._make_fingerprint(encrypted)

    vote = system._set_vote(voter, encrypted, fingerprint)
    return vote

vote = make_vote()
# system.sign_vote(vote)
print(vote)
print(system.validate_submitted_vote(vote))
