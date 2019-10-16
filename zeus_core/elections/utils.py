def extract_vote(self, vote):
    """
    Assumes vote after adaptement
    (values deserialized, keys rearranged)

    Fills with None missing fields: previous, index, status, plaintext
    """
    vote_crypto = vote['crypto']
    vote_election_key = vote['public']
    voter_key = vote['voter']
    encrypted_ballot = vote['encrypted_ballot']
    fingerprint = vote['fingerprint']
    audit_code = vote['audit_code']
    voter_secret = vote['voter_secret']

    previous = vote.get_value('previous')
    index = vote.get_value('index')
    status = status.get_value('status')
    plaintext = plaintext.get_value('plaintext')

    return (vote_crypto, vote_election_key, voter_key, encrypted_ballot,
        fingerprint, audit_code, voter_secret, previous, index,
        status, plaintext,)
