from crypto import ModPrimeCrypto, _2048_PRIME, _2048_PRIMITIVE, _2048_KEY, _2048_DDH,\
                                   _4096_PRIME, _4096_PRIMITIVE, _4096_KEY, _4096_DDH,\
                                   ModPrimeElement

p   = _4096_PRIME # _2048_PRIME
g0  = _4096_PRIMITIVE # _2048_PRIMITIVE
DDH = _4096_DDH # _2048_DDH

cryptosys = ModPrimeCrypto(modulus=p, primitive=g0) # Defaults to quadratic residues

import json
print('\n-- CRYPTOSYSTEM --\n%s' % json.dumps(cryptosys.system, indent=4, sort_keys=True))


# ------------------------------- External usage -------------------------------

# Generate key-pair along with proof-of-knowledge

key = cryptosys.keygen()
private_key = key['private']            # Access numerical value of private key
public_key = key['public']              # Contains also proof-of-knowledge

# Access numerical value of pubic key

print('\n-- PUBLIC KEY --\n%d' % cryptosys.get_as_integer(public_key))

# Verify knowledge of corresponding private key

key_validated = cryptosys.validate_key(public_key)
print('\n * Key validation: %s' % str(key_validated))

# Sign text-message and verify signature

message = 'SOS'

signed_message = cryptosys.sign_text_message(message, private_key)
verified = cryptosys.verify_text_signature(signed_message, public_key)

print('\n * Text-message signature validation: %s' % str(verified))


# ------------------------------- Internal usage -------------------------------

from gmpy2 import mpz
modulus = cryptosys.group.modulus

# Prove and verify knowledge of DDH

ddh = [ModPrimeElement(_, modulus) for _ in DDH['ddh']]
log = mpz(DDH['log'])

proof = cryptosys.chaum_pedersen_proof(ddh, log)
valid = cryptosys.chaum_pedersen_verify(ddh, proof)

print('\n * DDH proof validation: %s' % str(valid))

# Sign element and verify signature

element = ModPrimeElement(4450087957327360487628958739, modulus)

signature = cryptosys.sign_element(element, private_key)
verified = cryptosys.verify_element_signature(signature, public_key['value'])

print('\n * Signed element validation: %s' % str(verified))

# Encrypt element

message = ModPrimeElement(4450087957327360487628958739, modulus)
decryptor, cipher = cryptosys.encrypt_element(message, public_key['value'])

print('\n-- CIPHER --\n')
print('Decryptor\n')
print(decryptor)
print('\nCiphertext\n')
print(cipher)
print()
