def mk_ciphers(mixnet, nr_ciphers=12):
    random_element = mixnet.cryptosys.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

def mk_cipher_mix(mixnet, election_key, nr_ciphers=12):
    params = mixnet.cryptosys.hex_crypto_params()
    ciphers_to_mix = {
        'header': {
            'modulus': params['modulus'],
            'order': params['order'],
            'generator': params['generator'],
            'public': election_key.to_hex(),
        },
        'original_ciphers': [],
        'mixed_ciphers': mk_ciphers(mixnet, nr_ciphers),
        'cipher_collections': []
    }
    return ciphers_to_mix
