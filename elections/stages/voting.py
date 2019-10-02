from elections.abstracts import Stage
from elections.exceptions import Abortion
from elections.constants import (V_FINGERPRINT, V_INDEX, V_PREVIOUS, V_VOTER,
    V_ELECTION, V_ZEUS_PUBLIC, V_TRUSTEES, V_CANDIDATES, V_MODULUS, V_GENERATOR,
    V_ORDER, V_ALPHA, V_BETA, V_COMMITMENT, V_CHALLENGE, V_RESPONSE, V_COMMENTS)
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


    def verify_vote_signature(self, vote_signature):
        """
        Returns `True` if verified, otherwise raises `InvalidSignatureError`

        :type vote_signature: str
        :rtype: bool
        """
        message, _, exponent, c_1, c_2, _ = vote_signature.rsplit('\n', 5)

        (m00, m01, m02, m03, m04, m05, m06, m07, m08, m09,
            m10, m11, m12, m13, m14, m15, m16) = message.split('\n', 16)

        # Check signature structure

        if not ((m00.startswith(V_CAST_VOTE) or
            m00.startswith(V_AUDIT_REQUEST) or
            m00.startswith(V_PUBLIC_AUDIT) or
            m00.startswith(V_PUBLIC_AUDIT_FAILED) or
            m00.startswith('NONE')) or
            not m01.startswith(V_FINGERPRINT) or
            not m02.startswith(V_INDEX) or
            not m03.startswith(V_PREVIOUS) or
            not m04.startswith(V_ELECTION) or
            not m05.startswith(V_ZEUS_PUBLIC) or
            not m06.startswith(V_TRUSTEES) or
            not m07.startswith(V_CANDIDATES) or
            not m08.startswith(V_MODULUS) or
            not m09.startswith(V_ORDER) or
            not m10.startswith(V_GENERATOR) or
            not m11.startswith(V_ALPHA) or
            not m12.startswith(V_BETA) or
            not m13.startswith(V_COMMITMENT) or
            not m14.startswith(V_CHALLENGE) or
            not m15.startswith(V_RESPONSE) or
            not m16.startswith(V_COMMENTS)):
            e = 'Invalid vote signature structure'
            raise InvalidSignatureError(e)

        # Extract data

        status = m00
        fingerprint = m01[len(V_FINGERPRINT):]

        index_str = m02[len(V_INDEX):]
        if index_str == 'NONE':
            index = None
        elif index_str.isdigit():
            index = int(index_str)
        else:
            e = "Invalid vote index '%s'" % index_str
            raise InvalidSignatureError(e)

        previous = m03[len(V_PREVIOUS):]

        zeus_public_key = mpz(m05[len(V_ZEUS_PUBLIC):])
        zeus_public_key = self._set_public_key_from_value(zeus_public_key)

        _m06 = m06[len(V_TRUSTEES):]
        trustess = [int(_) for _ in _m06.split(' ')] if _m06 else []

        _m07 = m07[len(V_CANDIDATES):]
        candidates = _m07.split(' % ')

        modulus = mpz(m08[len(V_MODULUS):])
        order = mpz(m09[len(V_ORDER):])
        generator = mpz(m10[len(V_GENERATOR):])

        alpha = ModPrimeElement(mpz(m11[len(V_ALPHA):]), self.__modulus)
        beta = ModPrimeElement(mpz(m11[len(V_BETA):]), self.__modulus)

        commitment = mpz(m11[len(V_COMMITMENT):])
        challenge = mpz(m11[len(V_CHALLENGE):])
        response = mpz(m12[len(V_RESPONSE):])

        comments = m16[len(V_COMMENTS):]

        # Retrieve signed message

        exponent = mpz(exponent)
        c_1 = mpz(c_1)
        c_2 = mpz(c_2)
        signed_message = self._set_signed_message(message,
            signature=self._set_dsa_signature(exponent, c_1, c_2))

        # Validate signature or raise exception otherwise
        if not self.verify_text_signature(signed_message, zeus_public_key):
            e = 'Invalid vote signature'
            raise InvalidSignatureError(e)

        # Verify encryption proof or raise exception otherwise
        ciphertext = self.set_ciphertext(alpha, beta)
        proof = self._set_schnorr_proof(commitment, challenge, response)
        encrypted = self.set_ciphertext_proof(ciphertext, proof)
        # if index is not None and not self._verify_encryption(encrypted):
        if (index is not None and not self._verify_encryption(encrypted)):
            e = 'Invalid vote encryption'
            raise InvalidSignatureError(e)

        return True

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
        textified_vote += '\n-----------------\n'
        vote_signature += '%s\n%s\n%s\n' % (str(exponent), str(c_1), str(c_2))
        return vote_signature

    def textify_vote(self, vote, comments,
            cryptosys, zeus_public_key, trustees, candidates):

        (crypto, election_key, _, alpha, beta, commitment, challenge, response,
            fingerprint, _, _, previous, index, status, _) = self.extract_vote(vote)

        t00 = status if status is not None else 'NONE'
        t01 = '%s%s' % (V_FINGERPRINT, fingerprint)
        t02 = '%s%s' % (V_INDEX, ('%d' % index) if index is not None else 'NONE')
        t03 = '%s%s' % (V_PREVIOUS, (previous,)) 	# '%s%s' % (V_PREVIOUS, previous)
        t04 = '%s%s' % (V_ELECTION, str(election_key))
        t05 = '%s%s' % (V_ZEUS_PUBLIC, str(zeus_public_key))
        t06 = '%s%s' % (V_TRUSTEES, ' '.join(str(_) for _ in trustees))
        t07 = '%s%s' % (V_CANDIDATES, ' % '.join('%s' % _.encode('utf-8') for _ in candidates))

        # TODO: Make it cryptosystem agnostic
        t08 = ('%s%s' % (V_MODULUS, str(crypto['modulus'])),
               '%s%s' % (V_ORDER, str(crypto['order'])),
               '%s%s' % (V_GENERATOR, str(crypto['generator'])))

        t09 = '%s%s' % (V_ALPHA, str(alpha))
        t10 = '%s%s' % (V_BETA, str(beta))
        t11 = '%s%s' % (V_COMMITMENT, str(commitment))
        t12 = '%s%s' % (V_CHALLENGE, str(challenge))
        t13 = '%s%s' % (V_RESPONSE, str(response))
        t14 = '%s%s' % (V_COMMENTS, (comments,))

        textified = '\n'.join((t00, t01, t02, t03, t04, t05, t06, t07, *t08,
            t09, t10, t09, t10, t11, t12, t13, t14))
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

        if not cryptosys._verify_encryption(encrypted_ballot):
            e = 'Invalid ballot encryption'
            raise InvalidVoteError(e)
        if fingerprint != cryptosys.make_fingerprint(encrypted_ballot):
            e = 'Invalid fingerprint'
            raise InvalidVoteError(e)

        return fingerprint

    def extract_vote(self, vote, encode_func, to_exponent=int):
        """
        """
        crypto = vote['crypto']
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

        return (crypto,
                election_key,
                voter_key,
                alpha,
                beta,
                commitment,
                challenge,
                response,
                fingerprint,
                audit_code,
                voter_secret,
                previous,
                index,
                status,
                plaintext,)

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
