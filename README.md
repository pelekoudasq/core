## Example

```python
from crypto import ModPrimeCrypto, ModPrimeElement, _2048_PRIME, _2048_PRIMITIVE, _2048_DDH


# -------------------------------- External API --------------------------------

# No need to take care of provided arguments' types; common Python
# types like int and str may safely be provided at this level

# Generate mod p ElGamal systemtem, defaults to quadratic residues

system = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)

group = system.group                 # Access ElGamal systemtem's underlying group
system = system.system               # Access algebraic parameters (modulus, order, generator)

# Generate key-pair along with proof-of-knowledge (Schnorr)

key = system.keygen()
private_key = key['private']            # Access numerical value of private key
public_key = key['public']              # Contains also proof-of-knowledge

# Access numerical value of pubic key

print('\n-- PUBLIC KEY --\n%d' % system._extract_public_value(public_key))

# Verify knowledge of private key (no need to separate proof from public key)

key_validated = system.validate_public_key(public_key)

# Sign text-message and verify signature

message = 'SOS'

signed_message = system.sign_text_message(message, private_key)
verified = system.verify_text_signature(signed_message, public_key)


# -------------------------------- Internal API --------------------------------

# Take care of provided arguments' types at this level; mpz or ModPrimeElement
# have to be provided instead of common Python types like int or str
#
# Note: secrets (private keys, elements under encryption etc.) are usually
# involved in algebraic operations as exponents and are thus of type mpz;
# publics (public keys, encrypted messages etc.) belong by construction
# to the underlying ElGamal group and are always of type ModPrimeElement

from gmpy2 import mpz
modulus = system.group.modulus

# Prove and verify knowledge of DDH

ddh = [ModPrimeElement(_, modulus) for _ in _2048_DDH['ddh']]
log = mpz(_2048_DDH['log'])

proof = system._chaum_pedersen_proof(ddh, log)
valid = system._chaum_pedersen_verify(ddh, proof)

# Digital Signature Algorithm

exponent = mpz(9192283018239872384768709283019821039781928123817398172931839120)

signature = system._dsa_signature(exponent, private_key)
verified = system._dsa_verify(exponent, signature, public_key['value'])

# El-Gamal encryption and decryption of algebraic element

element = ModPrimeElement(4450087957327360487628958739, modulus)
ciphertext = system._encrypt(element, public_key['value'])
original = system._decrypt(ciphertext, private_key)
```

## Tests

```shell
pytest tests/
```

## Run example

```shell
python3 .
```

(or `python3 core/` from the project's parent directory)
