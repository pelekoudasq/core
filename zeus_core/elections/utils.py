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
