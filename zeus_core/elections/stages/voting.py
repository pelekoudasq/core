from zeus_core.elections.abstracts import Stage
from zeus_core.elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS,
    V_VOTER, V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS,
    V_GENERATOR, V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE,
    V_RESPONSE, V_COMMENTS, V_SEPARATOR)
from zeus_core.elections.exceptions import (Abortion, MalformedVoteError,
    ElectionMismatchError, VoteRejectionError, InvalidVoteError,)

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


    # Submission

    def cast_vote(self, vote):
        """
        Handles the submitted vote accordingly (audit-request or audit-vote
        or genuine vote) under account of inscribed parameters
        """
        election = self._get_controller()

        (_, _, voter_key, _, _, _, _, _, fingerprint,
            voter_audit_code, voter_secret, _, _, _, _,) = self.extract_vote(vote)

        try:
            voter, voter_audit_codes = self.detect_voter(voter_key)
        except (VoteRejectionError, Abortion,):
            # ~ Vote rejection: if voter's key could not be detected
            # ~ Election abortion: if voter's key has been detected
            # ~ but has not been assigned a set of audit codes
            raise

        if voter_secret:                          # secret published: audit-vote
            try:
                signature = self.submit_audit_vote(vote,
                        voter_audit_code, voter_audit_codes)
            except VoteRejectionError:
                # ~ Vote rejection: (1) No audit code provided, or (2) provided
                # ~ audit-code was not among the archived ones, or (3) no prior
                # ~ audit-request found for the provided fingerprint, or (4)
                # ~ voter's secret (randomness used at ballot encryption) was
                # ~ not provided within the submitted vote, or (5) vote failed
                # ~ to be verified as an audit-vote
                raise
        else:
            # ~ Voter does not publish the randomness used at ballot encryption:
            # ~ case 1: inscribed audit code is not among the archived ones:
            # ~ their vote is an audit-request
            # ~ case 2: inscribed audit code is among the inscribed ones or None:
            # ~ their vote is a genuine vote

            try:
                # ~ Voter audit code will not be None after that: if not coming
                # ~ with the vote, it will be set to one of the archived ones
                voter_audit_code = self.fix_audit_code(
                        voter_audit_code, voter_audit_codes)
            except VoteRejectionError:
                # ~ Vote rejection: if no audit code comes with
                # ~ the vote while skip-audit mode is disabled
                raise

            if voter_audit_code not in voter_audit_codes:        # audit-request
                try:
                    # ~ Sign the vote as audit-request and store it along
                    # ~ with inscribed fingerprint as key of the request
                    signature = self.submit_audit_request(fingerprint, voter_key, vote)
                except (VoteRejectionError,):
                    # ~ Request rejected: an audit-request has already been
                    # ~ submitted for the inscribed fingerprint
                    raise
            else:                                                 # genuine vote
                try:
                    signature = self.submit_genuine_vote(fingerprint, voter_key, vote)
                except (VoteRejectionError,):
                    # CONTINUE FROM HERE
                    #
                    raise

        return signature

    def detect_voter(self, voter_key):
        """
        Reject vote if the provided key could not be detected
        Abort election if key was detected but no audit codes correspond to it
        Return voter and audit codes otherwise
        """
        election = self._get_controller()

        voter = election.get_voter(voter_key)
        voter_audit_codes = election.get_voter_audit_codes(voter_key)
        if not voter:
            err = 'Invalid voter key'
            raise VoteRejectionError()
        elif not voter_audit_codes:
            err = 'Voter audit codes inconsistency'
            raise Abortion(err)

        return voter, voter_audit_codes

    def fix_audit_code(self, voter_audit_code, voter_audit_codes):
        """
        If provided, returns the voter's audit code
        If not provided and skip-audit mode is enabled, returns the first
        of the provided audit codes
        If not provided and skip-audit mode is disabled, vote is rejected
        (raises exception)
        """
        if not voter_audit_code:
            skip_audit = election.get_option('skip_audit')
            if skip_audit or skip_audit is None:
                voter_audit_code = voter_audit_codes[0]
            else:
                err = "No `audit_code` provided with the vote while \
                    `skip_audit` disabled"
                raise VoteRejectionError(err)
        return voter_audit_code


    def submit_audit_request(self, fingerprint, voter_key, vote):
        """
        Raises VoteRejectionError if an audit-request has already been
        submitted for the inscribed fingerprint.
        Otherwise: modifies the vote's status to audit-request, signs the vote
        and attach to it the signature, stores the audit-request, audit-vote
        and vote, and returns the signature
        """
        election = self._get_controller()
        if election.get_audit_request(fingeprint):
            err = "Audit-request for vote [%s] already submitted" % (fingeprint,)
            raise VoteRejectionError(err)

        # ~ Modify status
        vote['previous'] = ''
        vote['index'] = None
        vote['status'] = V_AUDIT_REQUEST

        # ~ Sign vote and attach signature
        comments = self.custom_audit_request_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        # ~ Store vote and audit-request
        election.store_audit_request(fingerprint, voter_key)
        election.store_audit_vote(fingerprint, vote)
        election.store_votes((vote,))

        return signature


    def submit_audit_vote(self, vote, voter_audit_code, voter_audit_codes):
        """
        """
        # ~ Check audit-publication prerequisites, reject otherwise
        if not voter_audit_code:
            err = "Invalid audit vote publication: No audit-code provided"
            raise VoteRejectionError(err)
        if voter_audit_code in audit_codes:
            err = "Invalid audit vote publication: Invalid audit-code provided"
            raise VoteRejectionError(err)
        if voter_key != audit_request:
            err = "No prior audit-request found for publish-request"
            raise VoteRejectionError(err)

        # ~ Audit-vote verification
        vote['previous'] = ''
        vote['index'] = None
        vote['status'] = V_PUBLIC_AUDIT
        missing, failed = self.verify_audit_votes(votes=[vote,])
        if missing:
            err = "Missing voter's secret: No randomness provided with audit-vote"
            raise VoteRejectionError(err)
        if failed:
            vote['status'] = V_PUBLIC_AUDIT_FAILED

        # ~ Sign message and attach signature
        comments = self.custom_audit_publication_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        # ~ Append vote and store inscribed fingerprint as audit-publication
        election.store_audit_publication(fingerprint)
        election.store_votes((vote,))

        return signature


    def submit_genuine_vote(self, fingerprint, voter_key, vote):
        """
        """
        if election.get_vote(fingerprint):
            err = "Vote [%s] already cast" % (fingerprint,)
            raise VoteRejectionError(err)
        voter_cast_votes = election.get_voter_cast_votes(voter_key)
        vote_limit = self.get_option('vote_limit')
        if vote_limit and len(voter_cast_votes) >= vote_limit:
            err = "Maximum number of votes reached: %s" % vote_limit
            raise VoteRejectionError(err)

        if not cast_votes:
            previous_fingerprint = ''
        else:
            previous_fingerprint = cast_votes[-1]

        vote = self.validate_submitted_vote(vote) # ---------------------------> implement...

        vote['previous'] = previous_fingerprint
        vote['status'] = V_CAST_VOTE
        vote['index'] = election.do_index_vote(fingerprint)

        comments = self.custom_cast_vote_message(vote)
        signature = self.sign_vote(vote, comments)
        vote['signature'] = signature

        election.append_vote(voter_key, fingerprint)
        election.store_votes((vote,))

        return signature


    def custom_audit_publication_message(self, vote):
        """
        """
        return ''

    def custom_audit_request_message(self, vote):
        """
        """
        return ''

    def custom_cast_vote_message(self, vote):
        """
        """
        return ''

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
        Admits JSON, converts keys and encrypted ballot to hex, returns text
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


    # Validation

    def validate_submitted_vote(self, vote):
        """
        Verfies proof of ballot encryption and checks if the vote's fingerprint
        is correct, returning the fingerprint in this case, otherwise
        InvalidVoteError is raised
        """
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        # FIXME
        _, encrypted, fingerprint, _, _, _, _, _, _ = self.extract_vote(vote)

        if not cryptosys.verify_encryption(encrypted):
            err = 'Encryption proof could not be verified'
            raise InvalidVoteError(err)

        if fingerprint != self.mk_fingerprint(encrypted):
            err = 'Fingerprint mismatch'
            raise InvalidVoteError(err)

        #
        #
        #
        #

        return fingerprint

    def mk_fingerprint(self, ciphertext_proof):
        """
        :rtype: bytes
        """
        fingerprint_params = self.get_fingerprint_params(ciphertext_proof)
        fingerprint = hash_texts(*[str(param) for param in fingerprint_params])
        return fingerprint


    # Audit vote verification

    def verify_audit_votes(self, audit_votes=None):
        """
        """
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
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
                self.extract_vote(vote)
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
