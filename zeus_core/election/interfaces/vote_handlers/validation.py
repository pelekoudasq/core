"""
"""

from abc import ABCMeta, abstractmethod

from zeus_core.utils import hash_nums, gamma_encoding_max
from zeus_core.election.constants import (MAX_VOTE_JSON_KEYS,
        MIN_VOTE_JSON_KEYS, ENC_BALLOT_JSON_KEYS)
from zeus_core.election.exceptions import InvalidVoteError


class VoteValidator(object, metaclass=ABCMeta):
    """
    Vote-validation interface to election server
    """

    @abstractmethod
    def get_cryptosys(self):
        """
        """

    @abstractmethod
    def get_crypto_params(self):
        """
        """

    @abstractmethod
    def get_election_key(self):
        """
        """

    @abstractmethod
    def get_candidates(self):
        """
        """

    @abstractmethod
    def get_audit_votes(self):
        """
        """

    @abstractmethod
    def extract_vote(self, vote):
        """
        """

    @abstractmethod
    def serialize_encrypted_ballot(self, encrypted_ballot):
        """
        """

    @abstractmethod
    def deserialize_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """


    def adapt_vote(self, vote):
        """
        Accepts JSON, performs deserialization, rearranges keys in accordance
        with cryptosys and mixnet operational requirements

        Fill with None missing fields: audit_code, voter_key

        Rejects in case of:
            - wrong or extra fields
            - missing fields
            - malformed encrypted ballot
            - cryptosystem mismatch
            - election key mismatch
        """
        cryptosys = self.get_cryptosys()
        crypto_params = self.get_crypto_params()
        crypto_param_keys = set(crypto_params.keys())

        # Check that vote does not contain extra or wrong fields
        if not set(vote.keys()).issubset(MAX_VOTE_JSON_KEYS):
            err = "Invalid vote content: Wrong or extra content provided"
            raise InvalidVoteError(err)

        # Check that vote includes the minimum necessary fields
        for key in MIN_VOTE_JSON_KEYS:
            if key not in vote:
                err = f"Invalid vote content: Field `{key}` missing from vote"
                raise InvalidVoteError(err)

        # Check if encrypted ballot fields are correct
        encrypted_ballot = vote['encrypted_ballot']
        if set(encrypted_ballot.keys()) != crypto_param_keys.union(ENC_BALLOT_JSON_KEYS):
            err = "Invalid vote content: Malformed encrypted ballot"
            raise InvalidVoteError(err)

        # Extract isncribed election key and main body values
        pop = encrypted_ballot.pop
        public = pop('public')
        alpha = pop('alpha')
        beta = pop('beta')
        commitment = pop('commitment')
        challenge = pop('challenge')
        response = pop('response')

        # Compare remaining content against server crypto; reject in case of mismatch
        vote_crypto = encrypted_ballot
        if vote_crypto != crypto_params:
            err = "Invalid vote content: Cryptosystem mismatch"
            raise InvalidVoteError(err)
        vote['crypto'] = vote_crypto

        # Check election key and reject in case of mismatch
        if cryptosys.int_to_element(public) != self.get_election_key():
        # if cryptosys.int_to_element(public) != self.get_election_key():
            err = "Invalid vote content: Election key mismatch"
            raise InvalidVoteError(err)
        vote['public'] = public

        # Deserialize encrypted ballot's main body
        encrypted_ballot = self.deserialize_encrypted_ballot(
            alpha, beta, commitment, challenge, response)
        vote['encrypted_ballot'] = encrypted_ballot

        # Leave audit-code as is (hexstring), or set to None if not provided
        if 'audit_code' not in vote:
            vote['audit_code'] = None

        # Deserialize voter-secret
        voter_secret = vote.get('voter_secret')
        vote['voter_secret'] = cryptosys.int_to_exponent(voter_secret) \
            if voter_secret else None

        # NOTE: fingerprint left as is (string)
        return vote


    def validate_genuine_vote(self, vote):
        """
        Raises InvalidVoteError if ballot encryption could not be verified or
        the provided fingerprint could not be retrieved from encrypted ballot
        """
        cryptosys = self.get_cryptosys()

        (_, _, _, encrypted_ballot, fingerprint, _, _, _, _, _, _) = \
            self.extract_vote(vote)

        # Verify ballot-encryption proof
        if not cryptosys.verify_encryption(encrypted_ballot):
            err = "Ballot encryption could not be verified"
            raise InvalidVoteError(err)

        # Check fingerprint match
        params = self.serialize_encrypted_ballot(encrypted_ballot)
        if fingerprint != hash_nums(*params).hex():
            err = "Fingerprint mismatch"
            raise InvalidVoteError(err)

        return fingerprint


    def validate_audit_votes(self, audit_votes=None):
        """
        """
        cryptosys = self.get_cryptosys()

        # ~ If no votes provided, verify all audit-votes from archive
        if not audit_votes:
            audit_votes = self.get_audit_votes()
            add_plaintext = 0
        else:
            add_plaintext = 1
        missing = []
        failed = []
        extract_vote = self.extract_vote
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
                failed.append(vote)
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
            election_key = self.get_election_key()
            decrypted = cryptosys.decrypt_with_randomness(ciphertext,
                election_key, voter_secret)
            nr_candidates = len(self.get_candidates())
            max_encoded = gamma_encoding_max(nr_candidates)
            if decrypted.value > max_encoded:
                failed.append(vote)
                continue
            # ~ Attach the above decrypted value to vote as plaintext if
            # ~ audit-votes had been initially provided for verification
            if add_plaintext:
                vote['plaintext'] = decrypted.value
        return missing, failed
