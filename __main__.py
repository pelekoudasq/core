from crypto import ModPrimeCrypto, _2048_PRIME, _2048_ELEMENT, _2048_KEY, _2048_DDH,\
                                   _4096_PRIME, _4096_ELEMENT, _4096_KEY, _4096_DDH


p   = _4096_PRIME # _2048_PRIME
g0  = _4096_ELEMENT # _2048_ELEMENT
DDH = _4096_DDH # _2048_DDH

cryptosys = ModPrimeCrypto(modulus=p, element=g0) # Defaults to quadratic residues

import json
print('\n-- CRYPTOSYSTEM --\n%s' % json.dumps(cryptosys.system, indent=4, sort_keys=True))

# Extract primitives

keygen = cryptosys.keygen

schnorr_proof = cryptosys.schnorr_proof                  # DL proof-of-knowledge
schnorr_verify = cryptosys.schnorr_verify

chaum_pedersen_proof = cryptosys.chaum_pedersen_proof    # DDH proof-of-knowledge
chaum_pedersen_verify = cryptosys.chaum_pedersen_verify

sign_element = cryptosys.sign_element
verify_element_signature = cryptosys.verify_element_signature

sign_text_message = cryptosys.sign_text_message
verify_text_signature = cryptosys.verify_text_signature

encrypt_element = cryptosys.encrypt_element

# Generate key pair along with proof of knowledge

private_key, public_key, proof = keygen(schnorr=True)

print('\n-- PUBLIC KEY --\n%d' % public_key)

# Verify knowledge of private key

valid = schnorr_verify(proof, public_key)

print('\n * Key validation: %s' % str(valid))

# Prove and verify knowledge of DDH

ddh = DDH['ddh']
log = DDH['log']

proof = chaum_pedersen_proof(ddh, log)
valid = chaum_pedersen_verify(ddh, proof)

print('\n * DDH proof validation: %s' % str(valid))

# Sign element and verify signature

element = 4458795732736487628958739

signature = sign_element(element, private_key)
verified = verify_element_signature(signature, public_key)

print('\n * Signed element validation: %s' % str(valid))

# Sign text and verify signature

message = 'SOS'

signed_message = sign_text_message(message, private_key)
verified = verify_text_signature(signed_message, public_key)

print('\n * Signed text validation: %s' % str(valid))

# Encrypt element

message = 3737843752384299791729921
decryptor, cipher = encrypt_element(message, public_key)

print('\n-- CIPHER --\n')
print('Decryptor\n')
print(decryptor)
print('\nCiphertext\n')
print(cipher)
print()
