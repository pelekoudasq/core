"""
Contains standalone interfaces for vote signing and vote-signature verification
"""

from abc import ABCMeta, abstractmethod

from zeus_core.election.constants import (V_CAST_VOTE, V_PUBLIC_AUDIT,
    V_PUBLIC_AUDIT_FAILED, V_AUDIT_REQUEST, V_FINGERPRINT, V_INDEX, V_PREVIOUS,
    V_VOTER, V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS,
    V_GENERATOR, V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE,
    V_RESPONSE, V_COMMENTS, V_SEPARATOR, NONE,)
from zeus_core.election.exceptions import (MalformedVoteError,
    ElectionMismatchError, InvalidVoteSignature)


class Signer(object, metaclass=ABCMeta):
    """
    Vote signing interface to election server
    """

    @abstractmethod
    def get_cryptosys(self):
        """
        """

    @abstractmethod
    def get_zeus_private_key(self):
        """
        """

    @abstractmethod
    def get_hex_zeus_public_key(self):
        """
        """

    @abstractmethod
    def get_hex_trustee_keys(self):
        """
        """

    @abstractmethod
    def get_hex_election_key(self):
        """
        """

    @abstractmethod
    def get_candidates(self):
        """
        """

    @abstractmethod
    def extract_vote(self):
        """
        """

    @abstractmethod
    def hexify_encrypted_ballot(self, encrypted_ballot):
        """
        """


    def sign_vote(self, vote, comments=[]):
        """
        Assumes vote after adaptment (values deserialized, keys rearranged)

        Will raise InvalidVoteSignature if after signing, if the produced
        vote is not verified
        """
        cryptosys = self.get_cryptosys()
        zeus_private_key = self.get_zeus_private_key()

        textified_vote = self.textify_vote(vote, comments)
        signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
        _, signature = cryptosys.extract_signed_message(signed_vote)
        vote_signature = self.format_vote_signature(textified_vote, signature)

        return vote_signature


    def textify_vote(self, vote, comments=[]):
        """
        Assumes vote after adaptment (values deserialized, keys rearranged)
        """
        cryptosys = self.get_cryptosys()

        hex_parameters = cryptosys.mk_hex_labels()
        hex_zeus_public_key = self.get_hex_zeus_public_key()
        hex_trustee_keys = self.get_hex_trustee_keys()
        hex_election_key = self.get_hex_election_key()
        candidates = self.get_candidates()

        (_, _, _, encrypted_ballot, fingerprint, _, _,
            previous, index, status, _) = self.extract_vote(vote)
        alpha, beta, commitment, challenge, response = \
            self.hexify_encrypted_ballot(encrypted_ballot)

        t00 = status if status is not None else NONE
        t01 = V_FINGERPRINT + fingerprint
        t02 = V_INDEX + f'{index if index is not None else NONE}'
        t03 = V_PREVIOUS + f'{previous if previous is not None else NONE}'
        t04 = V_ELECTION + hex_election_key
        t05 = V_ZEUS_PUBLIC + hex_zeus_public_key
        t06 = V_TRUSTEES + ' '.join(hex_trustee_keys)
        t07 = V_CANDIDATES + ' % '.join(candidates)
        t08, t09, t10 = hex_parameters
        t11 = V_ALPHA + alpha
        t12 = V_BETA + beta
        t13 = V_COMMITMENT + commitment
        t14 = V_CHALLENGE + challenge
        t15 = V_RESPONSE + response
        t16 = V_COMMENTS + f'{comments}'

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
            t09, t10, t11, t12, t13, t14, t15, t16))

        return textified


    def format_vote_signature(self, textified_vote, signature):
        """
        """
        cryptosys = self.get_cryptosys()

        vote_signature = ''
        vote_signature += textified_vote
        vote_signature += V_SEPARATOR
        vote_signature += cryptosys.hexify_dsa_signature(signature)

        return vote_signature


class Verifier(object):
    """
    Vote-signature verification interface to voter client
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
    def get_hex_election_key(self):
        """
        """

    @abstractmethod
    def get_hex_trustee_keys(self):
        """
        """

    @abstractmethod
    def get_candidates_set(self):
        """
        """

    @abstractmethod
    def unhexify_encrypted_ballot(self, alpha, beta,
            commitment, challenge, response):
        """
        """


    def verify_vote_signature(self, vote_signature):
        """
        Raise InvalidVoteSignature in case of:
            - malformed vote-text
            - election mismatch
            - invalid signature (failure of DSA signature validation)
            - invalid vote encryption (failure of voter to prove
                    knowledge of their signing key)
        """
        cryptosys = self.get_cryptosys()

        textified_vote, signature = self.split_vote_signature(vote_signature)
        try:
            vote_values = self.extract_textified_vote(textified_vote)
        except MalformedVoteError as err:
            raise InvalidVoteSignature(err)
        (_, _, index, previous, vote_election_key, zeus_public_key,
            vote_trustees, vote_candidates, vote_crypto,
            encrypted_ballot, _,) = vote_values

        try:
            self.verify_election(vote_crypto, vote_election_key,
                vote_trustees, vote_candidates)
        except ElectionMismatchError as err:
            raise InvalidVoteSignature(err)

        if index is not NONE and not cryptosys.verify_encryption(
                encrypted_ballot):
            err = "Invalid vote encryption"
            raise InvalidVoteSignature(err)

        # Essential signature validation
        # NOTE: uses zeus public key as extracted from vote
        signed_message = \
            cryptosys.set_signed_message(textified_vote, signature)
        if not cryptosys.verify_text_signature(signed_message, zeus_public_key):
            err = "Invalid vote signature"
            raise InvalidVoteSignature(err)

        return True


    def split_vote_signature(self, vote_signature):
        """
        Separate vote-text from attached DSA signature and return
        """
        cryptosys = self.get_cryptosys()

        textified_vote, attached_signature = vote_signature.split(V_SEPARATOR)
        dsa_signature = cryptosys.unhexify_dsa_signature(attached_signature)

        return textified_vote, dsa_signature


    def split_textified_vote(self, textified_vote):
        """
        Raise MalformedVoteError in case of malformed labels
        """
        cryptosys = self.get_cryptosys()

        (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16) = textified_vote.split('\n')

        # Check field labels
        if not ((t00.startswith(V_CAST_VOTE) or
                 t00.startswith(V_AUDIT_REQUEST) or
                 t00.startswith(V_PUBLIC_AUDIT) or
                 t00.startswith(V_PUBLIC_AUDIT_FAILED) or
                 t00.startswith(NONE)) or
                not t01.startswith(V_FINGERPRINT) or
                not t02.startswith(V_INDEX) or
                not t03.startswith(V_PREVIOUS) or
                not t04.startswith(V_ELECTION) or
                not t05.startswith(V_ZEUS_PUBLIC) or
                not t06.startswith(V_TRUSTEES) or
                not t07.startswith(V_CANDIDATES) or
                not cryptosys.check_labels(t08, t09, t10) or
                not t11.startswith(V_ALPHA) or
                not t12.startswith(V_BETA) or
                not t13.startswith(V_COMMITMENT) or
                not t14.startswith(V_CHALLENGE) or
                not t15.startswith(V_RESPONSE) or
                not t16.startswith(V_COMMENTS)):
            err = "Cannot verify vote signature: Malformed labels"
            raise MalformedVoteError(err)

        return (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16)


    def extract_textified_vote(self, textified_vote):
        """
        Extract and unhexifies (when needed) inscribed values from vote-text
        fields. Raise MalformedVoteError in case of inappropriate structure.
        """
        cryptosys = self.get_cryptosys()

        try:
            vote_fields = self.split_textified_vote(textified_vote)
        except MalformedVoteError:
            raise

        (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16) = vote_fields

        # Extract values
        status = t00
        fingerprint = t01[len(V_FINGERPRINT):]
        index = t02[len(V_INDEX):]
        if index != NONE and not index.isdigit():
            err = f"Invalid vote index: {index}"
            raise MalformedVoteError(err)
        previous = t03[len(V_PREVIOUS):]
        vote_election_key = t04[len(V_ELECTION):]   # will remain hexadecimal
        zeus_public_key = t05[len(V_ZEUS_PUBLIC):]
        trustees = t06[len(V_TRUSTEES):].split()    # will remain hexadecimals
        candidates_str = t07[len(V_CANDIDATES):]
        candidates = candidates_str.split(' % ') if candidates_str else []
        vote_crypto = cryptosys.unhexify_crypto_params(t08, t09, t10)
        alpha = t11[len(V_ALPHA):]
        beta = t12[len(V_BETA):]
        commitment = t13[len(V_COMMITMENT):]
        challenge = t14[len(V_CHALLENGE):]
        response = t15[len(V_RESPONSE):]
        comments = t16[len(V_COMMENTS):].split()

        zeus_public_key = cryptosys.hex_to_element(zeus_public_key)
        encrypted_ballot = self.unhexify_encrypted_ballot(
            alpha, beta, commitment, challenge, response)

        return (status, fingerprint, index, previous, vote_election_key,
            zeus_public_key, trustees, candidates, vote_crypto,
            encrypted_ballot, comments,)


    def verify_election(self, vote_crypto, vote_election_key,
            vote_trustees, vote_candidates):
        """
        Raise ElectionMismatchError if the extracted election parameters
        do not coincide with those of the running election
        """
        if vote_crypto != self.get_crypto_params():
            err = "Cannot verify vote signature: Cryptosystem mismatch"
            raise ElectionMismatchError(err)
        if vote_election_key != self.get_hex_election_key():
            err = "Cannot verify vote signature: Election key mismatch"
            raise ElectionMismatchError(err)
        if vote_trustees != self.get_hex_trustee_keys():
            err = "Cannot verify vote signature: Trustees mismatch"
            raise ElectionMismatchError(err)
        if set(vote_candidates) != self.get_candidates_set():
            err = "Cannot verify vote signature: Candidates mismatch"
            raise ElectionMismatchError(err)
        return True
