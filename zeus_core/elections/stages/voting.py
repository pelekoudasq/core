from zeus_core.elections.abstracts import Stage
from zeus_core.elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS,
    V_VOTER, V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS,
    V_GENERATOR, V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE,
    V_RESPONSE, V_COMMENTS, V_SEPARATOR, NONE,)
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


    # General vote handler

    def cast_vote(self, vote):
        """
        Handles the submitted vote accordingly (audit-request or audit-vote
        or genuine vote) under account of inscribed parameters

        Rejects in case of:

            (Adapt stage)
            - wrong or extra fields
            - missing fields
            - malformed encrypted ballot
            - cryptosystem mismatch
            - election key mismatch
        """
        election = self._get_controller()

        try:
            vote = self.adapt_vote(vote)
        except InvalidVoteError as err:
            # Wrong or extra or missing fields, or malformed encrypted ballot,
            # or cryptosystem mismatch, or election key mismatch
            raise VoteRejectionError(err)

        (_, _, voter_key, _, fingerprint, voter_audit_code, voter_secret, \
            _, _, _, _) = self.extract_vote(vote)

        try:
            voter, voter_audit_codes = self.detect_voter(voter_key)
        except (VoteRejectionError, Abortion,):
            # Voter's key could not be detected or voter's key detected
            # but not assigned any set of audit-codes
            raise

        if voter_secret:
            try:
                signature = self.submit_audit_vote(vote,
                        voter_audit_code, voter_audit_codes)
            except VoteRejectionError:
                # No audit-code provided, or provided audit-code was not among
                # the assigned ones, or no prior audit-request found for the
                # provided fingerprint, or voter's secret was not included, or
                # vote failed to be verified as audit, or produced vote-signature
                # failed to be verified
                raise
        else:
            try:
                # If no audit-code provided, choose one of the assigned ones
                voter_audit_code = self.fix_audit_code(
                        voter_audit_code, voter_audit_codes)
            except VoteRejectionError:
                # No audit-code provided while skip-audit mode disabled
                raise

            if voter_audit_code not in voter_audit_codes:
                try:
                    signature = self.submit_audit_request(
                        fingerprint, voter_key, vote)
                except (VoteRejectionError,):
                    # Audit-request already submitted for the provided fingerpint,
                    # or produced vote-signature failed to be verified
                    raise
            else:
                try:
                    signature = self.submit_genuine_vote(
                        fingerprint, voter_key, vote)
                except (VoteRejectionError,):
                    # Vote already cast, or vote limit reached, or vote failed to
                    # be validated, or produced vote-signature not verified
                    raise

        return signature


    # Adaptment/Extraction

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
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
        crypto_params = election.get_cryptoparams()
        crypto_param_keys = set(cryptoparams.keys())

        # Check that vote does not contain extra or wrong fields
        if not set(vote.keys()).issubset({'voter', 'encrypted_ballot',
            'fingerprint', 'audit_code', 'voter_secret'}):
            err = "Invalid vote content: Wrong or extra content provided"
            raise InvalidVoteError(err)

        # Check that vote includes the minimum necessary fields
        for key in ('voter', 'encrypted_ballot', 'fingreprint'):
            if key not in vote:
                err = f'Invalid vote content: Field `{key}` missing from vote'
                raise InvalidVoteError(err)

        # Check if encrypted ballot fields are correct
        encrypted_ballot = vote['encrypted_ballot']
        if set(encrypted_ballot.keys()) != crypto_param_keys.union({'public',
                'alpha', 'beta', 'commitment', 'challenge', 'response'}):
            err = 'Invalid vote content: Malformed encrypted ballot'
            raise InvalidVoteError(err)

        # Extract isncribed election key and main body values
        pop = encrypted_ballot.pop
        public = pop('public')
        alpha = pop('alpha')
        beta = pop('beta')
        commitment = pop('commitment')
        challenge = pop('challenge')
        response = pop('response')

        # Compare remaining content against server crypto;
        # reject in case of mismatch
        vote_crypto = encrypted_ballot
        if vote_crypto != crypto_params:
            err = 'Invalid vote content: Cryptosystem mismatch'
            raise InvalidVoteError(err)
        vote['crypto'] = vote_crypto

        # Check election key and reject in case of mismatch
        public = cryptosys.to_element(public)
        if public != election.get_election_key():
            err = 'Invalid vote content: Election key mismatch'
            raise InvalidVoteError(err)
        vote['public'] = public

        # Deserialize encrypted ballot's main body
        encrypted_ballot = cryptosys.deserialize_encrypted_ballot(
            alpha, beta, commitment, challenge, response)
        vote['encrypted_ballot'] = encrypted_ballot

        # Leave fingerprint as is (hexstring)
        vote['fingeprint'] = fingerprint

        # Leave audit-code as is (hexstring), or set to None if not provided
        if 'audit_code' not in vote:
            vote['audit_code'] = None

        # Deserialize voter-secret
        voter_secret = vote.get('voter_secret')
        vote['voter_secret'] = cryptosys.to_exponent(voter_secret) \
            if voter_secret else None

        return vote

    def extract_vote(self, vote):
        """
        Assumes vote after adaptement
        (values deserialized, keys rearranged)

        Fills with None missing fields: previous, index, status, plaintext
        """
        vote_crypto = vote['crypto']
        vote_public = vote['public']
        voter_key = vote['voter']
        encrypted_ballot = vote['encrypted_ballot']
        fingerprint = vote['fingerprint']
        audit_code = vote['audit_code']
        voter_secret = vote['voter_secret']

        previous = vote.get_value('previous')
        index = vote.get_value('index')
        status = status.get_value('status')
        plaintext = plaintext.get_value('plaintext')

        return (vote_crypto, vote_public, voter_key, encrypted_ballot,
            fingerprint, audit_code, voter_secret, previous, index,
            status, plaintext,)


    # Voter fixation

    def detect_voter(self, voter_key):
        """
        Reject vote if the provided key could not be detected
        Abort election if key was detected but no audit-codes correspond to it
        Return voter and audit-codes otherwise
        """
        election = self._get_controller()

        voter = election.get_voter(voter_key)
        voter_audit_codes = election.get_voter_audit_codes(voter_key)
        if not voter:
            err = 'Invalid voter key'
            raise VoteRejectionError()
        elif not voter_audit_codes:
            err = 'Voter audit-codes inconsistency'
            raise Abortion(err)

        return voter, voter_audit_codes

    def fix_audit_code(self, voter_audit_code, voter_audit_codes):
        """
        If provided, returns the voter's audit-code
        If not provided and skip-audit mode is enabled, returns the first
        of the provided audit-codes
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

    def exclude_voter(voter_key, reason=''):
        """
        """
        election = self._get_controller()
        election.store_excluded_voter(voter_key, reason)


    # Submissions

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

        # Modify status
        vote['status'] = V_AUDIT_REQUEST
        vote['previous'] = ''
        vote['index'] = None

        # Sign vote and attach signature
        comments = self.custom_audit_request_message(vote)
        try:
            signature = self.sign_vote(vote, comments)
        except InvalidSignatureError as err:
            raise VoteRejectionError(err)
        vote['signature'] = signature

        # Store vote along with audit-request
        election.store_audit_request(fingerprint, voter_key)
        election.store_audit_vote(fingerprint, vote)
        election.store_votes((vote,))

        return signature


    def submit_audit_vote(self, vote, voter_audit_code, voter_audit_codes):
        """
        Raises VoteRejectionError if
            - No audit-code provided
            - Invalid audit-code provided
            - No prior audit-request found for publish-request
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

        # Sign vote and attach signature
        comments = self.custom_audit_publication_message(vote)
        try:
            signature = self.sign_vote(vote, comments)
        except InvalidSignatureError as err:
            raise VoteRejectionError(err)
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

        try:
            self.validate_submitted_vote(vote)
        except InvalidVoteError as err:
            raise VoteRejectionError(err)

        vote['previous'] = previous_fingerprint
        vote['status'] = V_CAST_VOTE
        vote['index'] = election.do_index_vote(fingerprint)

        # Sign vote and attach signature
        comments = self.custom_cast_vote_message(vote)
        try:
            signature = self.sign_vote(vote, comments)
        except InvalidSignatureError as err:
            raise VoteRejectionError(err)
        vote['signature'] = signature

        election.append_vote(voter_key, fingerprint)
        election.store_votes((vote,))

        ##################################################################
        # DANGER: commit all data to disk before giving a signature out! #
        ##################################################################
        return signature


    # Vote signing

    def sign_vote(self, vote, comments):
        """
        Assumes vote after adaptment (values deserialized, keys rearranged)

        Will raise InvalidSignatureError if after signing, if the produced
        vote is not verified
        """
        election = self._get_controller()
        cryptosys = election.get_cryptosys()
        zeus_private_key = election.get_zeus_private_key()

        textified_vote = self.textify_vote(self, vote, comments)
        signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
        _, exponent, c_1, c_2 = cryptosys.extract_signed_message(signed_vote)
        vote_signature = self.format_vote_signature(textified_vote, exponent, c_1, c_2)

        self.verify_vote_signature(vote_signature)
        return vote_signature

    def textify_vote(self, vote, comments):
        """
        Assumes vote after adaptment (values deserialized, keys rearranged)
        """
        zeus_public_key = self.election.get_zeus_public_key()
        trustee_keys = self.election.get_trustee_keys() # hex strings
        candidates = self.election.get_candidates()

        # vote_crypto, vote_public, voter_key, encrypted_ballot,
        #     fingerprint, audit_code, voter_secret, previous, index,
        #     status, plaintext

        (crypto_params, election_key, _, alpha, beta, commitment, challenge, response,
            fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)


        t00 = status if status is not None else NONE
        t01 = V_FINGERPRINT + fingerprint
        t02 = V_INDEX + '%s' % (index if index is not None else NONE)
        t03 = V_PREVIOUS + '%s' % (previous,)
        t04 = V_ELECTION + '%x' % election_key
        t05 = V_ZEUS_PUBLIC + '%s' % zeus_public_key.to_hex()
        t06 = V_TRUSTEES + '%s' % ' '.join(trustee_keys)
        t07 = V_CANDIDATES + '%s' % ' % '.join(candidates)
        t08, t09, t10 = cryptosys.textify_params(vote_crypto)
        t11 = V_ALPHA + '%x' % alpha
        t12 = V_BETA + '%x' % beta
        t13 = V_COMMITMENT + '%x' % commitment
        t14 = V_CHALLENGE + '%x' % challenge
        t15 = V_RESPONSE + '%x' % response
        t16 = V_COMMENTS + '%s' % (comments,)

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
            t09, t10, t11, t12, t13, t14, t15, t6))
        return textified

    def format_vote_signature(self, textified_vote, exponent, c_1, c_2):
        """
        """
        textified_vote += V_SEPARATOR
        vote_signature += '%s\n%s\n%s\n' % (str(exponent), str(c_1), str(c_2))
        return vote_signature

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
                 t00.startswith(NONE)) or
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
        if index != NONE and not index.isdigit():
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
        alpha = cryptosys.to_element(int(alpha))
        beta = cryptosys.to_element(int(beta))
        commitment = cryptosys.to_exponent(commitment)
        challenge = cryptosys.to_exponent(challenge)
        response = cryptosys.to_exponent(response)

        return (status, fingerprint, index, previous, election_key,
            zeus_public_key, trustees, candidates, vote_crypto,
            alpha, beta, commitment, challenge, response, comments)


    # Vote-signature verification

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


    # Genuine vote validation

    def validate_submitted_vote(self, vote):
        """
        Assumes vote after adaptment (values deserialized, keys rearranged)

        Raises InvalidVoteError if ballot encryption could not be verified or
        the provided fingerprint could not be retrieved from encrypted ballot
        """
        election = self._get_controller()
        cryptosys = election.get_cryptosys()

        (_, _, _, encrypted_ballot, fingerprint,
            _, _, _, _, _, _) = self.extract_vote(vote)

        # Verify ballot-encryption proof
        if not cryptosys.verify_encryption(encrypted_ballot):
            err = 'Ballot encryption could not be verified'
            raise InvalidVoteError(err)

        # Check fingerprint match
        params = cryptosys.hexify_encrypted_ballot(encrypted_ballot)
        if fingerprint != hash_nums(params).hex():
            err = 'Fingerprint mismatch'
            raise InvalidVoteError(err)

        return fingerprint

    # Message customization

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
