"""
"""

# Vote handling

def adapt_vote(cryptosys, vote, deserialize=True):
    """
    Emulates vote adaptment from the server's side. No checks,
    only key rearrangement and values deserialization.
    """
    cast_element = cryptosys.int_to_element if deserialize else lambda x: x
    cast_exponent = cryptosys.int_to_exponent if deserialize else lambda x: x

    encrypted_ballot = vote['encrypted_ballot']
    pop = encrypted_ballot.pop
    public = pop('public')
    alpha = pop('alpha')
    beta = pop('beta')
    commitment = pop('commitment')
    challenge = pop('challenge')
    response = pop('response')
    vote['crypto'] = encrypted_ballot
    vote['public'] = public
    vote['encrypted_ballot'] = {
        'ciphertext': {
            'alpha': cast_element(alpha),
            'beta': cast_element(beta)
        },
        'proof': {
            'commitment': cast_element(commitment),
            'challenge': cast_exponent(challenge),
            'response': cast_exponent(response),
        }
    }
    if 'audit_code' not in vote:
        vote['audit_code'] = None
    voter_secret = vote.get('voter_secret')
    vote['voter_secret'] = cast_exponent(voter_secret) \
        if voter_secret else None
    return vote


def extract_vote(vote):
    """
    Assumes vote after adaptement (values deserialized, keys rearranged)

    Fills with None missing fields:
        previous, index, status, plaintext, audit_code, voter_secret
    """
    vote_crypto = vote['crypto']
    vote_election_key = vote['public']
    voter_key = vote['voter']
    encrypted_ballot = vote['encrypted_ballot']
    fingerprint = vote['fingerprint']

    get_value = vote.get
    previous = get_value('previous')
    index = get_value('index')
    status = get_value('status')
    plaintext = get_value('plaintext')
    audit_code = get_value('audit_code')
    voter_secret = get_value('voter_secret')

    return (vote_crypto, vote_election_key, voter_key, encrypted_ballot,
        fingerprint, audit_code, voter_secret, previous, index,
        status, plaintext,)


# JSON display

import json


def display_json(entity, length=16, trimmed=True):
    """
    Displays JSON object in terminal (trims long values by default)
    """
    to_display = trim_json(entity, length=length) \
        if trimmed else entity
    print(json.dumps(to_display, sort_keys=False, indent=4))


def trim_json(entity, length=16):
    """
    Returns a "copy" of the provided JSON with trimmed values for nice display
    """
    def trim_value(value, length=16):
        if type(value) is int:
            return int(f'{value}'[:length])
        elif type(value) is str:
            return f'{value}'[:length]
        elif type(value) is None:
            return ''

    if type(entity) is list:
        trimmed = []
        for elem in entity:
            if type(elem) in (list, dict):
                trimmed.append(trim_json(elem))
            else:
                trimmed.append(trim_value(elem))
    elif type(entity) is dict:
        trimmed = {}
        for key, value in entity.items():
            trimmed[key] = trim_value(value) if type(value) is not dict \
                else trim_json(value, length=length)
    return trimmed
