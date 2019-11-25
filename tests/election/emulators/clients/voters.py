"""
"""
from copy import deepcopy
from clients import Voter
from tests.election.utils import adapt_vote, extract_vote
from zeus_core.utils import (random_integer, random_selection, random_party_selection,
                            gamma_encoding_max, encode_selection)
from zeus_core.election.constants import VOTER_SLOT_CEIL


class VoterEmulator(Voter):
    """
    """

    # Communication

    def recv_election_params(self, params):
        """
        """
        cryptosys, election_key, candidates, voter_key, audit_codes = \
            self.extract_election_params(params)
        self.store_election_params(cryptosys, election_key, candidates,
                        voter_key, audit_codes)


    def send_vote(self, vote, election_server):
        """
        """
        pass


    # Random vote generation

    def mk_genuine_vote(self, corrupt_proof=False, corrupt_fingerprint=False,
            election_mismatch=False):
        """
        Audit code among the assigned ones. Voter's secret not advertised.
        """
        vote = self._mk_random_vote(selection=None,
            audit_code=None, publish=None)
        if corrupt_proof:
            enc_ballot = vote['encrypted_ballot']
            challenge = enc_ballot['challenge']
            response = enc_ballot['response']
            enc_ballot['challenge'] = response
            enc_ballot['response'] = challenge
        if corrupt_fingerprint:
            vote['fingerprint'] += '__corrupt_part'
        if election_mismatch:
            vote['encrypted_ballot']['public'] += 1
        return vote


    def mk_audit_request(self, selection=None, election_mismatch=False):
        """
        Make audit-vote without advertising voter's secret
        """
        audit_request = self.mk_audit_vote(publish=False,
            election_mismatch=election_mismatch)
        return audit_request


    def mk_audit_vote(self, publish=True, missing=False, corrupt_proof=False,
            corrupt_alpha=False, election_mismatch=False, corrupt_encoding=False,
            fake_nr_candidates=None):
        """
        Voter's secret by default advertised
        """
        random_hex = lambda: '%x' % random_integer(2, VOTER_SLOT_CEIL)
        audit_code = random_hex()
        while audit_code in self.get_audit_codes():
            audit_code = random_hex()
        if corrupt_encoding:
            audit_vote = self._mk_corrupt_encoding(fake_nr_candidates, audit_code)
        else:
            audit_vote = self._mk_random_vote(selection=None,
                    audit_code=audit_code, publish=publish)
            enc_ballot = audit_vote['encrypted_ballot']
            if missing:
                del audit_vote['voter_secret']
            if corrupt_proof:
                challenge = enc_ballot['challenge']
                response = enc_ballot['response']
                enc_ballot['challenge'] = response
                enc_ballot['response'] = challenge
            if corrupt_alpha:
                beta = enc_ballot['beta']
                enc_ballot['alpha'] = beta
            if election_mismatch:
                enc_ballot['public'] += 1
        return audit_vote


    def _mk_random_vote(self, selection, audit_code, publish):
        """
        """
        nr_candidates = len(self.get_candidates())
        if selection is None:
            if random_integer(0, 4) & 1:
                selection = random_selection(nr_candidates, full=False)
            else:
                selection = random_party_selection(nr_candidates, 2)
        encoded_selection = encode_selection(selection, nr_candidates)
        vote = self.mk_vote_from_encoded_selection(encoded_selection,
                audit_code, publish)
        voter_secret = vote.get('voter_secret')
        if voter_secret and not publish:
            del vote['voter_secret']
        return vote


    def _mk_corrupt_encoding(self, fake_nr_candidates, audit_code):
        """
        Meant to be used for testing audit-vote submission: make sure
        that the provided audit_code is not None
        """
        cryptosys = self.get_cryptosys()

        def get_decrypted_value(adapted_vote):
            _, _, _, encrypted_ballot, _, _, voter_secret, _, _, _, _ = \
                extract_vote(adapted_vote)
            ciphertext, _ = cryptosys.extract_ciphertext_proof(encrypted_ballot)
            election_key = self.get_election_key()
            decrypted = cryptosys.decrypt_with_randomness(ciphertext,
                election_key, voter_secret).value
            return decrypted

        audit_vote = self._mk_random_vote(selection=None,
                            audit_code=audit_code, publish=True)
        copy = deepcopy(audit_vote)
        adapted_vote = adapt_vote(cryptosys, copy)
        while get_decrypted_value(adapted_vote) <= \
            gamma_encoding_max(fake_nr_candidates):
            audit_vote = self._mk_random_vote(selection=None,
                            audit_code=audit_code, publish=True)
            copy = deepcopy(audit_vote)
            adapted_vote = adapt_vote(cryptosys, copy)
        return audit_vote
