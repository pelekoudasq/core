## Example

```python
from crypto import ModPrimeCrypto, ModPrimeElement, _2048_PRIME, _2048_PRIMITIVE, _2048_DDH


# ----------------------------- External interface -----------------------------

# No need to take care of provided arguments' types; common Python
# types like int and str may safely be provided at this level

# Generate mod p ElGamal cryptosystem, defaults to quadratic residues

cryptosys = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)

group = cryptosys.group                 # Access ElGamal cryptosystem's underlying group
system = cryptosys.system               # Access algebraic parameters (modulus, order, generator)

# Generate key-pair along with proof-of-knowledge (Schnorr)

key = cryptosys.keygen()
private_key = key['private']            # Access numerical value of private key
public_key = key['public']              # Contains also proof-of-knowledge

# Access numerical value of pubic key

print('\n-- PUBLIC KEY --\n%d' % cryptosys.get_as_integer(public_key))

# Verify knowledge of private key (no need to separate proof from public key)

key_validated = cryptosys.validate_key(public_key)

# Sign text-message and verify signature

message = 'SOS'

signed_message = cryptosys.sign_text_message(message, private_key)
verified = cryptosys.verify_text_signature(signed_message, public_key)


# ----------------------------- Internal interface -----------------------------

# Take care of provided arguments' types at this level; mpz or ModPrimeElement
# have to be provided instead of common Python types like int or str
#
# Note: secrets (private keys, elements under encryption etc.) are usually
# involved in algebraic operations as exponents and are thus of type mpz;
# publics (public keys, encrypted messages etc.) belong by construction
# to the underlying ElGamal group and are always of type ModPrimeElement

from gmpy2 import mpz
modulus = cryptosys.group.modulus

# Prove and verify knowledge of DDH

ddh = [ModPrimeElement(_, modulus) for _ in _2048_DDH['ddh']]
log = mpz(_2048_DDH['log'])

proof = cryptosys._chaum_pedersen_proof(ddh, log)
valid = cryptosys._chaum_pedersen_verify(ddh, proof)

# Sign algebraic element and verify signature

element = ModPrimeElement(4450087957327360487628958739, modulus)

signature = cryptosys._sign_element(element, private_key)
verified = cryptosys._verify_element_signature(signature, public_key['value'])

# Encrypt algebraic element

message = ModPrimeElement(4450087957327360487628958739, modulus)
decryptor, cipher = cryptosys._encrypt_element(message, public_key['value'])
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
