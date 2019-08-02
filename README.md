## Example

```python
from crypto import ModPrimeCrypto, ModPrimeElement, _2048_PRIME, _2048_PRIMITIVE, _2048_DDH

cryptosys = ModPrimeCrypto(modulus=p, primitive=g0) # Defaults to quadratic residues


# ------------------------------- External usage -------------------------------

# Generate key-pair along with proof-of-knowledge

key = cryptosys.keygen()
private_key = key['private']            # Access numerical value of private key
public_key = key['public']              # Contains also proof-of-knowledge

# Access numerical value of pubic key

public_key_value = public_key['value'].value

# Verify knowledge of corresponding private key

key_validated = cryptosys.validate_key(public_key)

# Sign text-message and verify signature

message = 'SOS'

signed_message = cryptosys.sign_text_message(message, private_key)
verified = cryptosys.verify_text_signature(signed_message, public_key['value'])


# ------------------------------- Internal usage -------------------------------

# Prove and verify knowledge of DDH

ddh = [ModPrimeElement(_, cryptosys.group.modulus) for _ in DDH['ddh']]
log = DDH['log']

proof = cryptosys.chaum_pedersen_proof(ddh, log)
valid = cryptosys.chaum_pedersen_verify(ddh, proof)

# Sign element and verify signature

element = ModPrimeElement(4450087957327360487628958739, cryptosys.group.modulus)

signature = cryptosys.sign_element(element, private_key)
verified = cryptosys.verify_element_signature(signature, public_key['value'])

# Encrypt element

message = ModPrimeElement(4450087957327360487628958739, cryptosys.group.modulus)
decryptor, cipher = cryptosys.encrypt_element(message, public_key['value'])
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
