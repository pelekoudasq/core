from crypto import ModPrimeCrypto, _2048_PRIME, _2048_ELEMENT, _2048_KEY,\
                                   _4096_PRIME, _4096_ELEMENT, _4096_KEY

p  = _4096_PRIME # _2048_PRIME
g0 = _4096_ELEMENT # _2048_ELEMENT

cryptosys = ModPrimeCrypto(modulus=p, element=g0) # Defaults to quadratic residues

import json
print(json.dumps(cryptosys.system, indent=4, sort_keys=True))

# Extract primitives
keygen = cryptosys.keygen
encrypt_element = cryptosys.encrypt_element
schnorr_proof = cryptosys.schnorr_proof
schnorr_verify = cryptosys.schnorr_verify

# Generate key pair

private_key, public_key =  keygen()

# print('\n-- PUBLIC KEY --\n')
# print(public_key)

# Prove and verify knowledge of private key

extras = [0, 7, 11, 666]
proof = schnorr_proof(private_key, public_key, *extras)
valid = schnorr_verify(proof, public_key, *extras)
print(valid)
#
# # Encrypt element
#
# message = 373784375
# decryptor, cipher = encrypt_element(message, public_key)
#
# print('\n-- CIPHER --\n')
# print('Decryptor\n')
# print(decryptor)
# print('\nCiphertext\n')
# print(cipher)
# print()
