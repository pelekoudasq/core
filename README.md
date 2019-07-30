## Example

```python
from crypto import ModPrimeCrypto, _2048_PRIME, _2048_ELEMENT, _2048_KEY

# Create cryptosystem (defaults to quadratic residues)

cryptosys = ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT)

# Extract primitives

keygen = cryptosys.keygen
encrypt_element = cryptosys.encrypt_element
schnorr_proof = cryptosys.schnorr_proof
schnorr_verify = cryptosys.schnorr_verify

# Generate key pair

private_key, public_key =  keygen()

# Encrypt element

message = 373784375
decryptor, cipher = encrypt_element(message, public_key)

# Prove and verify knowledge of private key

extras = [0, 7, 11, 666]
proof = schnorr_proof(private_key, public_key, *extras)
valid = schnorr_verify(proof, public_key, *extras)
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
