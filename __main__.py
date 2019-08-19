from crypto import ModPrimeCrypto, _2048_PRIME, _2048_PRIMITIVE, _2048_KEY, _2048_DDH,\
                                   _4096_PRIME, _4096_PRIMITIVE, _4096_KEY, _4096_DDH,\
                                   ModPrimeElement

p   = _4096_PRIME # _2048_PRIME
g0  = _4096_PRIMITIVE # _2048_PRIMITIVE
DDH = _4096_DDH # _2048_DDH


# -------------------------------- External API --------------------------------

system = ModPrimeCrypto(modulus=p, primitive=g0) # Defaults to quadratic residues

import json
print('\n-- CRYPTOSYSTEM --\n%s' % json.dumps(system.system, indent=4, sort_keys=True))

group = system.group                 # Access ElGamal systemtem underlying group

# Generate key-pair along with proof-of-knowledge

key = system.keygen()
private_key = system._extract_private(key)            # Access numerical value (mpz) of private key
public_key = system.extract_public(key)              # Contains also proof-of-knowledge

# Access numerical value of pubic key

print('\n-- PUBLIC KEY --\n%d' % system.extract_value(public_key))

# Verify knowledge of corresponding private key

key_validated = system.validate_key(public_key)
print('\n * Key validation: %s' % str(key_validated))

# Sign text-message and verify signature

message = 'SOS'

signed_message = system.sign_text_message(message, private_key)
print(signed_message)
verified = system.verify_text_signature(signed_message, public_key)

print('\n * Text-message signature validation: %s' % str(verified))


# -------------------------------- Internal API --------------------------------

from gmpy2 import mpz
modulus = group.modulus

# Extract numerical (mpz) value of public key

public_key = system._extract_public(key)

# Prove and verify knowledge of DDH

ddh = [ModPrimeElement(_, modulus) for _ in DDH['ddh']]
log = mpz(DDH['log'])

proof = system._chaum_pedersen_proof(ddh, log)
valid = system._chaum_pedersen_verify(ddh, proof)

print('\n * DDH proof validation: %s' % str(valid))

# Sign and verify signature under the DSA-Scheme

exponent = mpz(919228301823987238476870928301982103978254287481928123817398172931839120)

signature = system._dsa_signature(exponent, private_key)
verified = system._dsa_verify(exponent, signature, public_key)
print('\n * Exponent signature validation: %s' % str(verified))

# El-Gamal encryption and decryption of algebraic element

element = ModPrimeElement(4450087957327360487628958739, modulus)
ciphertxt = system._encrypt(element, public_key)

print('\n-- CIPHERTEXT --\n')
print('Decryptor\n')
print(ciphertxt['alpha'])
print('\nEncrypted element\n')
print(ciphertxt['beta'])
print()

original = system._decrypt(ciphertxt, private_key)

print('\n * ElGamal decryption success: %s\n' % str(original==element))

# Encryption proof

randomness = system.group.random_exponent()
ciphertxt = system._encrypt(element, public_key, randomness)
proof = system._prove_encryption(ciphertxt, randomness)
verified = system._verify_encryption(proof, ciphertxt)

print('\n * ElGamal encryption verified: %s\n' % str(verified))
