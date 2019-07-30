from crypto import ModPrimeCrypto, _2048_PRIME, _2048_ELEMENT, _2048_KEY,\
                                   _4096_PRIME, _4096_ELEMENT, _4096_KEY

p  = _4096_PRIME # _2048_PRIME
g0 = _4096_ELEMENT # _2048_ELEMENT

cryptosys = ModPrimeCrypto(modulus=p, element=g0) # Defaults to quadratic residues

import json
print(json.dumps(cryptosys.system, indent=4, sort_keys=True))

# Extract primitives
keygen = cryptosys.keygen
schnorr_proof = cryptosys.schnorr_proof
schnorr_verify = cryptosys.schnorr_verify
sign_element = cryptosys.sign_element
verify_element_signature = cryptosys.verify_element_signature
encrypt_element = cryptosys.encrypt_element

# Generate key pair along with proof of knowledge

private_key, public_key, proof = keygen(schnorr=True)

print('\n-- PUBLIC KEY --\n')
print(public_key)

# Prove and verify knowledge of private key

valid = schnorr_verify(proof, public_key)
print(valid)

# Sign element and verify signature

element = 4458795732736487628958739

signature = sign_element(element, private_key)
verified = verify_element_signature(signature, public_key)
print(verified)


# Encrypt element

message = 373784375
decryptor, cipher = encrypt_element(message, public_key)

print('\n-- CIPHER --\n')
print('Decryptor\n')
print(decryptor)
print('\nCiphertext\n')
print(cipher)
print()
