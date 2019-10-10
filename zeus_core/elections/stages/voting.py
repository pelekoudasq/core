from zeus_core.elections.abstracts import Stage
from zeus_core.elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS, V_VOTER,
    V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS, V_GENERATOR,
    V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE, V_RESPONSE, V_COMMENTS,
    V_SEPARATOR)
from zeus_core.elections.exceptions import (Abortion, MalformedVoteError,
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

    # Vote textification

    def extract_encrypted_ballot(self, encrypted_ballot):
        """
        Admits JSON and extracts WITHOUT deserializing
        """
        cryptosys = self.cryptosys
        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)

        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_proof(proof)

        return alpha, beta, commitment, challenge, response

    def extract_vote(self, vote, encode_func, to_exponent=int):
        """
        Admits JSO and extracts WITHOUT deserializing
        """
        crypto_params = vote['crypto']
        election_key = vote['public']
        voter_key = vote['voter']
        alpha, beta, commitment, challenge, response = \
            self.extract_encrypted_ballot(vote['encrypted_ballot'])
        fingerprint = vote['fingerprint'] # hash_encode(vote['fingerprint'])

        audit_code = vote.get_value('audit_code') # extract_value(vote, 'audit_code', int)
        voter_secret = vote.get_value('voter_secret') # extract_value(vote, 'voter_secret', to_exponent) # mpz
        previous = vote.get_value('previous') # extract_value(vote, 'previous', hash_encode)
        index = vote.get_value('index') # vote['index'] # extract_value(vote, 'index', int)
        status = status.get_value('status') # vote['status'] # extract_value(vote, 'status', str)
        plaintext = plaintext.get_value('plaintext') # extract_value(vote, 'plaintext', encode_func)

        return (crypto_params, election_key, voter_key, alpha, beta, commitment,
                challenge, response, fingerprint, audit_code, voter_secret,
                previous, index, status, plaintext,)

    def textify_vote(self, vote, comments):
        """
        Admits JSON, converts keys and encrypted ballot to hex, and returns text
        """
        (crypto_params, election_key, _, alpha, beta, commitment, challenge, response,
            fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)

        zeus_public_key = self.election.get_zeus_public_key()
        trustee_keys = self.election.get_trustee_keys()         # hex strings
        candidates = self.election.get_candidates()

        t00 = status if status is not None else 'NONE'
        t01 = V_FINGERPRINT + fingerprint                       # already hex
        t02 = V_INDEX + '%s' % (index if index is not None else 'NONE')
        t03 = V_PREVIOUS + '%s' % (previous,)
        t04 = V_ELECTION + '%x' % election_key
        t05 = V_ZEUS_PUBLIC + '%s' % zeus_public_key.to_hex()
        t06 = V_TRUSTEES + '%s' % ' '.join(trustee_keys)
        t07 = V_CANDIDATES + '%s' % ' % '.join(candidates)
        t08, t09, t10 = cryptosys.textify_params(crypto_params)
        t11 = V_ALPHA + '%x' % alpha
        t12 = V_BETA + '%x' % beta
        t13 = V_COMMITMENT + '%x' % commitment
        t14 = V_CHALLENGE + '%x' % challenge
        t15 = V_RESPONSE + '%x' % response
        t16 = V_COMMENTS + '%s' % (comments,)

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
            t09, t10, t11, t12, t13, t14, t15, t6))
        return textified


    # Vote signing

    def format_vote_signature(self, textified_vote, exponent, c_1, c_2):
        textified_vote += V_SEPARATOR
        vote_signature += '%s\n%s\n%s\n' % (str(exponent), str(c_1), str(c_2))
        return vote_signature

    def sign_vote(self, vote, comments, cryptosys, zeus_private_key,
            zeus_public_key, trustees, candidates):
        """
        """
        textfied_vote = self.textify_vote(self, vote, comments, cryptosys,
            zeus_public_key, trustees, candidates)
        signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
        _, exponent, c_1, c_2 = cryptosys.extract_signed_message(signed_vote)

        vote_signature = self.format_vote_signature(textified_vote, exponent, c_1, c_2)
        return vote_signature


    # Vote-signature verification

    def extract_vote_signature(self, cryptosys, vote_signature):
        """
        Separate vote-text from DSA signature and return
        """
        textified_vote, _, exponent, c_1, c_2, _ = \
            vote_signature.rsplit('\n', 5)                          # Split the provided text
        signature = \
            cryptosys.deserialize_dsa_signature(exponent, c1, c2)   # Retrieve DSA signature

        return textified_vote, signature

    def split_textified_vote(self, cryptosys, textified_vote):
        """
        Split vote-text to fields.
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
        election_key = cryptosys.deserialize_public_key(mpz(election_key))
        zeus_public_key = cryptosys.deserialize_public_key(mpz(zeus_public_key))
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

        # Verify proof of encryption
        ciphertext = cryptosys.set_ciphertext(alpha, beta)
        proof = cryptosys.set_schnorr_proof(commitment, challenge, response)
        if index is not None and not cryptosys.verify_encryption({
            'ciphertext': ciphertext,
            'proof': proof
        }):
            err = 'Invalid vote encryption'
            raise InvalidSignatureError(err)

        # Validate DSA signature (NOTE: uses zeus key as inscribed in vote)
        signed_message = \
            cryptosys.set_signed_message(textified_vote, signature)
        if not cryptosys.verify_text_signature(signed_message, zeus_public_key):
            err = 'Invalid vote signature'
            raise InvalidSignatureError(err)

        return True

    def exclude_voter(voter_key, reason=''):
        election = self._get_controller()
        election.store_excluded_voter(voter_key, reason)


    # Verifications and casting

    def verify_audit_votes(self, cryptosys, audit_votes=None):
        """
        """
        election = self._get_controller()
        nr_candidates = len(election.get_candidates())

        if not votes:
            audit_requests = election.get_audit_requests()
            get_vote = election.get_vote
            audit_votes = [get_vote(fingerprint) for fingerprint in audit_requests]
            add_plaintext = 0
        else:
            add_plaintext = 1


        missing = []
        failed = []
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


    def cast_vote(self, vote):
        """
        """
        election = self._get_controller()                                       # Setup

        (_, _, voter_key, _, _, _, _, _, fingerprint,
            voter_audit_code, voter_secret, _, _, _, _,) = self.extract_vote(vote)

        voter = election.get_voter(voter_key)
        voter_audit_codes = election.get_voter_audit_codes(voter_key)
        if not voter and not voter_audit_codes:
            err = 'Invalid voter key'
            raise Abortion(err)
        if not voter or not voter_audit_codes:
            err = 'Voter audit code inconsistency'
            raise Abortion(err)

        audit_request = election.get_audit_request(fingeprint)

        # # # # # # # # # # # #
        #
        # # TODO: replace everything below with a snipset like the following:
        #
        # if voter_secret:
        #     self.submit_audit_publication(...)
        # else:
        #     if not voter_audit_code:                                                # ...?
        #         skip_audit = election.get_option('skip_audit')
        #         if skip_audit or skip_audit is None:                                # Skip auditing for submission simplicity
        #             voter_audit_code = voter_audit_codes[0]
        #         else:
        #             err = "Invalid vote submission: No `audit_code` provided \
        #                 while `skip_audit` disabled"
        #             raise Abortion(err) # -----------------------------------------> change exception
        #
        #     if voter_audit_code not in voter_audit_codes:
        #         self.submit_audit_request(...)
        #     else:
        #         self.submit_genuine_vote(...)
        #
        # # # # # # # # # # # #

        if voter_secret:                                                        # Audit-publication
            if not voter_audit_code:
                err = "Invalid audit vote publication: No audit-code provided"
                raise Abortion(err) # -----------------------------------------> change exception...
            if voter_audit_code in audit_codes:
                err = "Invalid audit vote publication: Invalid audit-code provided"
                raise Abortion(err) # -----------------------------------------> change exception...
            if voter_key != audit_request:
                err = "No prior audit-request found for publish-request"
                raise Abortion(err) # -----------------------------------------> change exception...
            vote['previous'] = ''
            vote['index'] = None
            vote['status'] = V_PUBLIC_AUDIT
            comments = self.custom_audit_publication_message(vote)  # ---------> implement....
            missing, failed = self.verify_audit_votes(votes=[vote,])
            if missing:
                err = "Audit-publication failed: Missing voters' secrets"
                raise Abortion(err) # -----------------------------------------> change exception...
            if failed:
                vote['status'] = V_PUBLIC_AUDIT_FAILED
            comments = self.custom_audit_publication_message(vote)
            signature = self.sign_vote(vote, comments)
            vote['signature'] = signature
            election.store_audit_publication(fingerprint)
            election.store_votes((vote,))

            return signature

        if not voter_audit_code:                                                # ...?
            skip_audit = election.get_option('skip_audit')
            if skip_audit or skip_audit is None:                                # Skip auditing for submission simplicity
                voter_audit_code = voter_audit_codes[0]
            else:
                err = "Invalid vote submission: No `audit_code` provided \
                    while `skip_audit` disabled"
                raise Abortion(err) # -----------------------------------------> change exception


        if voter_audit_code not in voter_audit_codes:                           # Audit-request submission
            if audit_request:
                err = "Audit request for vote [%s] already exists" % (fingeprint,)
                raise Abortion(err)
            vote['previous'] = ''
            vote['index'] = None
            vote['status'] = V_AUDIT_REQUEST
            comments = self.custom_audit_request_message(vote)
            signature = self.sign_vote(vote, comments)
            vote['signature'] = signature
            election.store_audit_request(fingerprint, voter_key)
            election.store_votes((vote,))

            return signature

        if election.get_vote(fingerprint):                                      # Genuine vote submission
            err = "Vote [%s] already cast" % (fingerprint,)
            raise Abortion(err)
        voter_cast_votes = election.get_voter_cast_votes(voter_key)
        vote_limit = self.get_option('vote_limit')
        if vote_limit and len(voter_cast_votes) >= vote_limit:
            err = "Maximum number of votes reached: %s" % vote_limit
            raise Abortion(err) # ---------------------------------------------> change exception....

        if not cast_votes:
            previous_fingerprint = ''
        else:
            previous_fingerprint = cast_votes[-1]

        vote = self.validate_submitted_vote(vote) # ---------------------------> implement...

        vote['previous'] = previous_fingerprint
        vote['status'] = V_CAST_VOTE
        vote['index'] = election.do_index_vote(fingerprint)

        comments = self.custom_cast_vote_message(vote) # ----------------------> implement
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        election.append_vote(voter_key, fingerprint)
        election.store_votes((vote,))

        return signature
