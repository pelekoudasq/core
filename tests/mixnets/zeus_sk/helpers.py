def _make_ciphers(mixnet, nr_ciphers=12):
    random_element = mixnet.cryptosystem.group.random_element
    return [(random_element(), random_element()) for _ in range(nr_ciphers)]

def _make_ciphers_to_mix(mixnet, election_key, nr_ciphers=12):
    params = mixnet.cryptosystem.parameters
    ciphers_to_mix = {
        'modulus': params['modulus'],
        'order': params['order'],
        'generator': params['generator'],
        'public': election_key,
        'original_ciphers': [],
        'mixed_ciphers': _make_ciphers(mixnet, nr_ciphers),
        'cipher_collections': []
    }
    return ciphers_to_mix
