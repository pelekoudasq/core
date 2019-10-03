from elections.abstracts import Stage
from elections.exceptions import Abortion
from elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS, V_VOTER,
    V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS, V_GENERATOR,
    V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE, V_RESPONSE, V_COMMENTS,
    V_SEPARATOR)
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


    def verify_vote_signature(self, cryptosys, vote_signature):
        """
        Returns ``True`` if verified, otherwise raises ``InvalidSignatureError``
        """
        textified_vote, signature = self.extract_vote_signature(cryptosys, vote_signature)
        try:
            (_, _, index, _, zeus_public_key, _,_, _, _, _, alpha, beta,
            commitment, challenge, response,) = \
                self.extract_textified_vote(textified_vote)
        except InvalidSignatureError:
            raise

        # Validate signature, or raise exception otherwise
        signed_message = cryptosys.set_signed_message(textified_vote, signature)
        if not cryptosys.verify_text_signature(signed_message, zeus_public_key):
            err = 'Invalid vote signature'
            raise InvalidSignatureError(err)

        # Verify proof of encryption, or raise exception otherwise
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
        textified_vote, _, exponent, c_1, c_2, _ = vote_signature.rsplit('\n', 5)
        exponent = cryptosys.to_exponent(exponent)
        c_1 = cryptosys.to_exponent(c_1)
        c_2 = cryptosys.to_exponent(c_2)
        signature = cryptosys.set_dsa_signature(exponent, c_1, c_2)
        return textified_vote, signature


    def extract_textified_vote(self, textified_vote):
        """
        Will raise InvalidSignatureError if inscribed parameters
        concerning the cryptosystem and election configuration
        do not coincide with those of Zeus
        """
        (t00, t01, t02, t03, t04, t05, t06, t07, t08, t09,
            t10, t11, t12, t13, t14, t15, t16) = textified_vote.split('\n', 16)

        # Check structure of textified vote
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
            not cryptosys.verify_textified_params(t07, t08, t09) or
            not t11.startswith(V_ALPHA) or
            not t12.startswith(V_BETA) or
            not t13.startswith(V_COMMITMENT) or
            not t14.startswith(V_CHALLENGE) or
            not t15.startswith(V_RESPONSE) or
            not t16.startswith(V_COMMENTS)):
            err = 'Invalid vote signature structure'
            raise InvalidSignatureError(err)

        status = t00
        fingerprint = t01[len(V_FINGERPRINT):]
        index_str = t02[len(V_INDEX):]
        if index_str == 'NONE':
            index = None
        elif index_str.isdigit():
            index = int(index_str)
        else:
            err = "Invalid vote index '%s'" % index_str
            raise InvalidSignatureError(err)
        previous = t03[len(V_PREVIOUS):]

        # -------------------------------------------------
        # TODO: ?
        zeus_public_key = cryptosys.set_public_key_from_value(
            t05[len(V_ZEUS_PUBLIC):])
        # TODO: verify inscribed trustees
        trustees_str = t06[len(V_TRUSTEES):]
        trustess = [int(_) for _ in trustees_str.split(' ')] \
            if trustees_str else []
        # TODO: verify inscribed candidates
        candidates_str = t07[len(V_CANDIDATES):]
        candidates = candidates_str.split(' % ')
        # TODO: verify inscribed crypto params
        modulus = mpz(t08[len(V_MODULUS):])
        order = mpz(t09[len(V_ORDER):])
        generator = mpz(t10[len(V_GENERATOR):])
        # -------------------------------------------------

        alpha = cryptosys.encode_integer(int(t11[len(V_ALPHA):]))
        beta = cryptosys.encode_integer(int(t11[len(V_BETA):]))
        commitment = cryptosys.to_exponent(t11[len(V_COMMITMENT):])
        challenge = cryptosys.to_exponent(t11[len(V_CHALLENGE):])
        response = cryptosys.to_exponent(t12[len(V_RESPONSE):])

        return (status, fingerprint, index, previous, zeus_public_key, trustees,
                candidates, modulus, order, generator, alpha, beta,
                commitment, challenge, response,)


    def sign_vote(self, vote, comments, cryptosys, zeus_private_key,
            zeus_public_key, trustees, candidates):
        """
        NOTE: extract values of trustees' public keys before feeding them to this function!!!!
        trustees = [cryptosys.get_value(trustee) for trustee in trustees]
        """
        textfied_vote = self.textify_vote(self, vote, comments, cryptosys,
            zeus_public_key, trustees, candidates)
        signed_vote = cryptosys.sign_text_message(textified_vote, zeus_private_key)
        _, exponent, c_1, c_2 = cryptosys.extract_signed_message(signed_vote)

        vote_signature = self.format_vote_signature(textified_vote, exponent, c_1, c_2)

        return vote_signature

    def format_vote_signature(self, textified_vote, exponent, c_1, c_2):
        textified_vote += V_SEPARATOR
        vote_signature += '%s\n%s\n%s\n' % (str(exponent), str(c_1), str(c_2))
        return vote_signature

    def textify_vote(self, vote, comments,
            cryptosys, zeus_public_key, trustees, candidates):

        (crypto_params, election_key, _, alpha, beta, commitment, challenge, response,
            fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)

        t00 = status if status is not None else 'NONE'
        t01 = V_FINGERPRINT + '%s' % fingerprint
        t02 = V_INDEX + '%d' % (index if index is not None else 'NONE')
        t03 = V_PREVIOUS + '%s' % (previous,) 	# '%s%s' % (V_PREVIOUS, previous)
        t04 = V_ELECTION + '%s' % str(election_key)
        t05 = V_ZEUS_PUBLIC + '%s' % str(zeus_public_key)
        t06 = V_TRUSTEES + '%s' % ' '.join(str(_) for _ in trustees)
        t07 = V_CANDIDATES + '%s' % ' % '.join('%s' % _.encode('utf-8') for _ in candidates)

        t08, t09, t10 = cryptosys.textify_params(crypto_params)

        t11 = V_ALPHA + '%s' % str(alpha)
        t12 = V_BETA + '%s' % str(beta)
        t13 = V_COMMITMENT + '%s' % str(commitment)
        t14 = V_CHALLENGE + '%s' % str(challenge)
        t15 = V_RESPONSE + '%s' % str(response)
        t16 = V_COMMENTS + '%s' % (comments,)

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, t08,
            t09, t10, t11, t12, t13, t14, t15, t6))
        return textified

    def validate_submitted_vote(self, cryptosys, vote):
        """
        Verifies the inscribed encryption proof, checks if the vote's
        fingerprint is correct and returns the fingerprint

        If not, it raises InvalidVoteError

        :type vote: dict
        :rtype: bytes
        """
        encrypted_ballot = vote['encrypted_ballot']
        fingerprint = vote['fingerprint']

        if not cryptosys.verify_encryption(encrypted_ballot):
            err = 'Invalid ballot encryption'
            raise InvalidVoteError(err)
        if fingerprint != cryptosys.make_fingerprint(encrypted_ballot):
            err = 'Invalid fingerprint'
            raise InvalidVoteError(err)

        return fingerprint

    def extract_vote(self, vote, encode_func, to_exponent=int):
        """
        """
        crypto_params = vote['crypto']
        election_key = vote['public']
        voter_key = vote['voter']
        alpha, beta, commitment, challenge, response = \
            self.extract_encrypted_ballot(vote['encrypted_ballot'])
        fingerprint = hash_encode(vote['fingerprint'])

        audit_code = extract_value(vote, 'audit_code', int)
        voter_secret = extract_value(vote, 'voter_secret', to_exponent) # mpz
        previous = extract_value(vote, 'previous', hash_encode)
        index = extract_value(vote, 'index', int)
        status = extract_value(vote, 'status', str)
        plaintext = extract_value(vote, 'plaintext', encode_func)

        return (crypto_params, election_key, voter_key, alpha, beta, commitment,
                challenge, response, fingerprint, audit_code, voter_secret,
                previous, index, status, plaintext,)

    def extract_encrypted_ballot(self, cryptosys, encrypted_ballot):
        ciphertext, proof = cryptosys.extract_ciphertext_proof(encrypted_ballot)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_proof(proof)
        return alpha, beta, commitment, challenge, response

    def vote_from_plaintext(self, cryptosys, election_key, voter_key,
            plaintext, audit_code=None, publish=None):
        """
        """
        plaintext = cryptosys.encode_integer(plaintext)
        ciphertext, voter_secret = cryptosys._encrypt(encoded_plaintext,
                        election_key, get_secret=True)
        proof = cryptosys.prove_encryption(ciphertext, randomness)

        encrypted_ballot = self.make_encrypted_ballot(cryptosys, ciphertext, proof)
        fingerprint = self.make_fingerprint(cryptosys, encrypted_ballot)

        vote = self.set_vote(cryptosys, election_key, voter_key,
            encrypted_ballot, fingerprint, audit_code, publish, voter_secret)
        return vote


    def vote_from_encoded_selection(self, cryptosys, election_key, voter_key,
            encoded_selection, audit_code=None, publish=None):
        """
        """
        encoded_selection = cryptosys.encode_integer(encoded_selection)
        ciphertext, randomness = cryptosys._encrypt(encoded_selection,
                        election_key, get_secret=True)
        proof = cryptosys.prove_encryption(ciphertext, randomness)

        encrypted_ballot = self.make_encrypted_ballot(cryptosys, ciphertext, proof)
        fingerprint = cryptosys.make_fingerprint(cryptosys, encrypted_ballot)
        voter_secret = randomness if publish else None

        vote = self.set_vote(cryptosys, election_key, voter_key,
            encrypted_ballot, fingerprint, audit_code, publish, voter_secret)
        return vote


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


    def make_encrypted_ballot(self, cryptosys, election_key, ciphertext, proof):
        encrypted_ballot = cryptosys.set_ciphertext_proof(ciphertext, proof)
        return encrypted_ballot


    def make_fingerprint(self, cryptosys, ciphertext_proof):
        """
        Makes fingerprint out of a dictionary of the form

        {
            'ciphertext': {
                'alpha': GroupElement,
                'beta': GroupElement
            },
            'proof': dict
        }

        :type ciphertext_proof: dict
        :rtype: bytes
        """
        fingerprint_params = self.get_fingerprint_params(cryptosys, ciphertext_proof)
        fingerprint = hash_texts(*[str(_) for _ in fingerprint_params])
        return fingerprint

    def get_fingerprint_params(self, cryptosys, ciphertext_proof):
        """
        """
        ciphertext, proof = cryptosys.extract_ciphertext_proof(ciphertext_proof)
        alpha, beta = cryptosys.extract_ciphertext(ciphertext)
        commitment, challenge, response = cryptosys.extract_schnorr_proof(proof)
        return alpha, beta, commitment, challenge, response
