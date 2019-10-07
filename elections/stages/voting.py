from elections.abstracts import Stage
from elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS, V_VOTER,
    V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS, V_GENERATOR,
    V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE, V_RESPONSE, V_COMMENTS,
    V_SEPARATOR)
from elections.exceptions import (Abortion, MalformedVoteError,
    ElectionMismatchError)

from .mixing import Mixing


class Voting(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Mixing)

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        return ()

    def _update_controller(self, *generated):
        pass

    def verify_audit_votes(self, cryptosys, audit_votes=None):
        """
        """
        election = self._get_controller()
        nr_candidates = len(election.get_candidates())

        missing = []
        failed = []


        if not votes:
            audit_requests = election.get_audit_requests()
            get_vote = election.get_vote
            audit_votes = [get_vote(fingerprint) for fingerprint in audit_requests]
            add_plaintext = 0
        else:
            add_plaintext = 1

        for vote in audit_votes:
            _, _, _, encrypted_ballot, _, _, voter_secret, _, _, _, _ = \
                self.extract_vote(vote)

            if not voter_secret:
                missing.append(vote)
                continue
            if not cryptosys.verify_encryption(encrypted_ballot):
                failed.append(note)
                continue

            ciphertext, _ = cryptosys.extract_ciphertext_proof(encrypted_ballot)
            alpha_vote, _ = cryptosys.extract_ciphertext(ciphertext)
            alpha = cryptosys.group.generate(voter_secret)
            if alpha_vote != alpha:
                failed.append(vote)
                continue

            encoded = cryptosys.decrypt_with_randomness(election_key,
                ciphertext, voter_secret)

            max_encoded = gamma_encoding_max(nr_candidates)
            if encoded.value > max_encoded:
                failed.append(vote)
                continue
            if add_plaintext:
                vote['plaintext'] = encoded.value

        return missing, failed


    def verify_vote_signature(self, cryptosys, vote_signature):
        """
        Raise InvalidSignatureError in case of:
            - malformed vote-text
            - election mismatch
            - invalid signature (failure of DSA signature validation)
            - invalid vote encryption (failure of voter to prove
                    knowledge of their signing key)
        """
        # Retrieve vote-text and accompanying DSA-signature
        textified_vote, signature = \
            self.extract_vote_signature(cryptosys, vote_signature)

        # Extract values from vote-text
        try:
            vote_values = self.extract_textified_vote(textified_vote)
        except MalformedVoteError as err:
            raise InvalidSignatureError(err)
        (status, fingerprint, index, previous, election_key, zeus_public_key,
        trustees, candidates, vote_crypto, alpha, beta,
        commitment, challenge, response, comments,) = vote_values

        # Verify inscribed election info
        try:
            self.verify_election(vote_crypto, election_key, trustees, cadidates)
        except ElectionMismatchError as err:
            raise InvalidSignatureError(err)

        # Validate DSA signature (NOTE: uses zeus key as inscribed in vote)
        signed_message = \
            cryptosys.set_signed_message(textified_vote, signature)
        if not cryptosys.verify_text_signature(signed_message, zeus_public_key):
            err = 'Invalid vote signature'
            raise InvalidSignatureError(err)

        # Verify proof of encryption
        ciphertext = cryptosys.set_ciphertext(alpha, beta)
        proof = cryptosys.set_schnorr_proof(commitment, challenge, response)
        if index is not None and not cryptosys.verify_encryption({
            'ciphertext': ciphertext,
            'proof': proof
        }):
            err = 'Invalid vote encryption'
            raise InvalidSignatureError(err)

        return True


    def extract_vote_signature(self, cryptosys, vote_signature):
        """
        Separates vote-text and retrieves accompanying DSA-signature
        """
        # Split the provided text
        textified_vote, _, exponent, c_1, c_2, _ = \
            vote_signature.rsplit('\n', 5)

        # Retrieve DSA signature
        to_exponent = cryptosys.to_exponent
        exponent = to_exponent(exponent)
        c_1 = to_exponent(c_1)
        c_2 = to_exponent(c_2)
        signature = cryptosys.set_dsa_signature(exponent, c_1, c_2)

        return textified_vote, signature


    def split_textified_vote(self, cryptosys, textified_vote):
        """
        Split vote test to fields.
        Raise MalformedVoteError in case of malformed labels
        """
        (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16) = textified_vote.split('\n', 16)

        # Check field labels
        if not ((t00.startswith(V_CAST_VOTE) or
                 t00.startswith(V_AUDIT_REQUEST) or
                 t00.startswith(V_PUBLIC_AUDIT) or
                 t00.startswith(V_PUBLIC_AUDIT_FAILED) or
                 t00.startswith('NONE')) or
            not t01.startswith(V_FINGERPRINT) or
            not t02.startswith(V_INDEX) or
            not t03.startswith(V_PREVIOUS) or
            not t04.startswith(V_ELECTION) or
            not t05.startswith(V_ZEUS_PUBLIC) or
            not t06.startswith(V_TRUSTEES) or
            not t07.startswith(V_CANDIDATES) or
            not cryptosys.check_textified_params(t07, t08, t09) or
            not t11.startswith(V_ALPHA) or
            not t12.startswith(V_BETA) or
            not t13.startswith(V_COMMITMENT) or
            not t14.startswith(V_CHALLENGE) or
            not t15.startswith(V_RESPONSE) or
            not t16.startswith(V_COMMENTS)):
            err = 'Cannot verify vote signature: Malformed labels'
            raise MalformedVoteError(err)

        return (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16)

    def extract_textified_vote(self, cryptosys, textified_vote):
        """
        Extract inscribed values from vote-text
        Raise MalformedVoteError in case of inappropriate structure
        """
        try:
            vote_fields = self.split_textified_vote(cryptosys, textified_vote)
        except MalformedVoteError:
            raise

        (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16) = vote_fields

        # Extract field values
        status = t00
        fingerprint = t01[len(V_FINGERPRINT):]
        index = t02[len(V_INDEX):]
        if index != 'NONE' and not index.isdigit():
            err = f"Invalid vote index: {index}"
            raise MalformedVoteError(err)
        previous = t03[len(V_PREVIOUS):]
        election_key = t04[len(V_ELECTION):]
        zeus_public_key = t05[len(V_ZEUS_PUBLIC):]
        trustees = t06[len(V_TRUSTEES):].split()
        candidates_str = t07[len(V_CANDIDATES):]
        candidates = candidates_str.split(' % ') if candidates_str else []
        vote_crypto = cryptosys.mk_vote_crypto(t08, t09, t10)
        alpha = t11[len(V_ALPHA):]
        beta = t12[len(V_BETA):]
        commitment = t13[len(V_COMMITMENT):]
        challenge = t14[len(V_CHALLENGE):]
        repsonse = t15[len(V_RESPONSE):]
        comments = t16[len(V_COMMENTS):].split()

        # Convert remaining texts to corresponding algebraic objects
        election_key = cryptosys.set_public_key_from_value(mpz(election_key))
        zeus_public_key = cryptosys.set_public_key_from_value(mpz(zeus_public_key))
        alpha = cryptosys.encode_integer(int(alpha))
        beta = cryptosys.encode_integer(int(beta))
        commitment = cryptosys.to_exponent(commitment)
        challenge = cryptosys.to_exponent(challenge)
        response = cryptosys.to_exponent(response)

        return (status, fingerprint, index, previous, election_key,
            zeus_public_key, trustees, candidates, vote_crypto,
            alpha, beta, commitment, challenge, response, comments)

    def verify_election(self, vote_crypto, election_key, trustees, candidates):
        """
        Verifies that the election parameters extracted from a submitted
        vote coincide with those of the current election.
        Raise ElectionMismatchError otherwise.
        """
        election = self._get_controller()
        if vote_crypto != election.get_crypto_params():
            err = "Cannot verify vote signature: Cryptosystem mismatch"
            raise ElectionMismatchError(err)
        if election_key != election.get_election_key():
            err = "Cannot verify vote signature: Election key mismatch"
            raise ElectionMismatchError(err)
        if set(trustees) != set(election.get_trustees()):
            err = "Cannot verify vote signature: Trustees mismatch"
            raise ElectionMismatchError(err)
        if set(candidates) != set(election.get_candidates()):
            err = "Cannot verify vote signature: Election key mismatch"
            raise ElectionMismatchError(err)
        return True

    def exclude_voter(voter_key, reason=''):
        election = self._get_controller()
        election.store_excluded_voter(voter_key, reason)

    # Vote structure

    def set_vote(self, cryptosys, election_key, voter_key, encrypted_ballot,
            fingerprint, audit_code=None, publish=None, voter_secret=None,
            previous=None, index=None, status=None, plaintext=None):
        """
        """
        vote = {}

        vote['crypto'] = cryptosys.parameters()
        vote['public'] = election_key
        vote['voter'] = voter_key
        vote['encrypted_ballot'] = encrypted_ballot
        vote['fingerprint'] = hash_decode(fingerprint)

        if audit_code:
            vote['audit_code'] = audit_code
        if publish:
            vote['voter_secret'] = voter_secret
        if previous:
            vote['index'] = index
        if status:
            vote['status'] = status
        if plaintext:
            vote['plaintext'] = plaintext

        return vote

    def extract_vote(self, vote, encode_func, to_exponent=int):
        """
        """
        crypto_params = vote['crypto']
        election_key = vote['public']
        voter_key = vote['voter']
        encrypted_ballot = vote['encrypted_ballot']
        # alpha, beta, commitment, challenge, response = \
        #     self.extract_encrypted_ballot(vote['encrypted_ballot'])
        fingerprint = hash_encode(vote['fingerprint'])

        audit_code = vote.get('audit_code')
        voter_secret = vote.get('voter_secret')
        previous = vote.get('previous')
        index = vote.get('index')
        status = vote.get('status')
        plaintext = vote.get('plaintext')

        return (crypto_params, election_key, voter_key, encrypted_ballot,
            fingerprint, audit_code, voter_secret, previous, index, status,
            plaintext,)

    def retrieve_fingerprint_params(self, cryptosys, encrypted_ballot):
        """
        """
        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
        return alpha, beta, commitment, challenge, response

    # def extract_encrypted_ballot(self, cryptosys, encrypted_ballot):
    #     ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
    #     alpha, beta = cryptosys.extract_ciphertext(ciphertext)
    #     commitment, challenge, response = cryptosys.extract_proof(proof)
    #     return alpha, beta, commitment, challenge, response
