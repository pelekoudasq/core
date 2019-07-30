## Example

```python
from crypto import ModPrimeCrypto, _2048_PRIME, _2048_ELEMENT

# Make cryptosystem (defaults to quadratic residues)

cryptosys = ModPrimeCrypto(modulus=_2048_PRIME, element=_2048_ELEMENT)

# Extract primitives

keygen = cryptosys.keygen
schnorr_proof = cryptosys.schnorr_proof
schnorr_verify = cryptosys.schnorr_verify
sign_element = cryptosys.sign_element
verify_element_signature = cryptosys.verify_element_signature
encrypt_element = cryptosys.encrypt_element

# Generate key pair along with proof of knowledge

private_key, public_key, proof = keygen(schnorr=True)

# Prove and verify knowledge of private key

valid = schnorr_verify(proof, public_key)

# Sign element and verify signature

element = 4458795732736487628958739

signature = sign_element(element, private_key)
verified = verify_element_signature(signature, public_key)

# Sign text and verify signature

message = 'SOS'

signed_message = sign_text_message(message, private_key)
verified = verify_text_signature(signed_message, public_key)
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
