"""
Contains standalone interface for vote-validation
"""
from zeus_core.utils import hash_nums
from zeus_core.elections.utils import extract_vote
from zeus_core.elections.exceptions import InvalidVoteError

class Validator(object):
    """
    """
    def __init__(self, election):
        self.election = election
        self.cryptosys = election.get_cryptosys()


    def validate_genuine_vote(self, vote):
        """
        Raises InvalidVoteError if ballot encryption could not be verified or
        the provided fingerprint could not be retrieved from encrypted ballot
        """
        election = self.election
        cryptosys = self.cryptosys

        (_, _, _, encrypted_ballot, fingerprint, _, _, _, _, _, _) = \
            extract_vote(vote)

        # Verify ballot-encryption proof
        if not cryptosys.verify_encryption(encrypted_ballot):
            err = 'Ballot encryption could not be verified'
            raise InvalidVoteError(err)

        # Check fingerprint match
        params = cryptosys.serialize_encrypted_ballot(encrypted_ballot)
        if fingerprint != hash_nums(*params).hex():
            err = 'Fingerprint mismatch'
            raise InvalidVoteError(err)

        return fingerprint


    def validate_audit_votes(self, audit_votes=None):
        """
        """
        election = self.election
        cryptosys = self.cryptosys

        # ~ If no votes provided, verify all audit-votes from archive
        if audit_votes:
            audit_votes = election.get_audit_votes()
            add_plaintext = 0
        else:
            add_plaintext = 1
        missing = []
        failed = []
        for vote in audit_votes:
            _, _, _, encrypted_ballot, _, _, voter_secret, _, _, _, _ = \
                extract_vote(vote)
            # ~ Check if acclaimed randomness used at ballot encryption comes with
            # ~ the vote; otherwise sort as `missing` and proceed to next vote
            if not voter_secret:
                missing.append(vote)
                continue
            ciphertext, _ = cryptosys.extract_ciphertext_proof(encrypted_ballot)
            # ~ Check if voter has knowledge of the randomness used at ballot
            # ~ encryption; otherwise sort as `failed` and proceed to next vote
            if not cryptosys.verify_encryption(encrypted_ballot):
                failed.append(note)
                continue
            # ~ Check if acclaimed randomness has indeed been used at ballot
            # ~ encryption; otherwise sort as `failed` and proceed to next vote
            alpha_vote, _ = cryptosys.extract_ciphertext(ciphertext)
            alpha = cryptosys.group.generate(voter_secret)
            if alpha_vote != alpha:
                failed.append(vote)
                continue
            # ~ Check if max-gamma-encoding of candidates' number remains smaller
            # ~ than decrypting the encrypted ballot with the acclaimed
            # ~ randomness; otherwise sort as failed and proceed to next vote
            decrypted = cryptosys.decrypt_with_randomness(ciphertext,
                election_key, voter_secret)
            nr_candidates = len(election.get_candidates())
            max_encoded = gamma_encoding_max(nr_candidates)
            if decrypted.value > max_encoded:
                failed.append(vote)
                continue
            # ~ Attach the above decrypted value to vote as plaintext if
            # ~ audit-votes had been initially provided for verification
            if add_plaintext:
                vote['plaintext'] = decrypted.value
        return missing, failed
