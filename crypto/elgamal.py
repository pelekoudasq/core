from abc import ABCMeta, abstractmethod
from functools import partial

from .exceptions import WrongCryptoError, WeakCryptoError
from utils import extract_value, hash_encode, hash_decode


class ElGamalCrypto(object, metaclass=ABCMeta):
    """
    Abstract class for ElGamal systemtems
    """

# -------------------------------- External API --------------------------------

    # Access

    @property
    @abstractmethod
    def parameters(self):
        """
        Returns a dictionary with the systemtem's parameters
        """

    @property
    @abstractmethod
    def group(self):
        """
        Returns the systemtem's underlying group
        """

    @property
    @abstractmethod
    def GroupElement(self):
        """
        Returns the class whose instances are the group elements of the cryptosystem
        """

    # Key generation

    @abstractmethod
    def keygen(self, private_key=None, schnorr=True):
        """
        Generates a pair of a private and a public key, the latter
        accompanied by a proof-of-knowledge of the former
        """

    @abstractmethod
    def validate_public_key(self, public_key):
        """
        Validates the proof-of-knowledge coming attached in the provided
        public key (refers to knowledge of the corresponding private key)
        """

    # Digital signatures

    @abstractmethod
    def sign_text_message(self, message, private_key):
        """
        Signs the provided message with the provided private key under the
        ElGamal Signature Scheme.
        """

    @abstractmethod
    def verify_text_signature(self, signed_message, public_key):
        """
        Verifies that the signature attached in the provided message
        belongs to the holder of the provided public key
        """

    # Encryption/Decryption

# -------------------------------- Internal API --------------------------------

    # Access

    @abstractmethod
    def _parameters(self):
        """
        """
        pass

    @abstractmethod
    def _extract_ciphertext(self, ciphertext):
        """
        """
        pass

    # Schnorr protocol

    @abstractmethod
    def _schnorr_proof(self, secret, public, *extras):
        """
        Implementation of Schnorr protocol from the prover's side (non-interactive)

        Returns proof-of-knowldge of the discrete logarithm x (`secret`) of y (`public`).
        `*extras` are to be used in the Fiat-Shamir heuristic. The proof has the form
        """

    @abstractmethod
    def _schnorr_verify(self, proof, public, *extras):
        """
        Implementation of Schnorr protocol from the verifier's side (non-interactive)

        Validates the demonstrated proof-of-knowledge (`proof`) of the discrete logarithm of
        y (`public`). `*extras` are assumed to have been used in the Fiat-Shamir heuristic
        """

    # Chaum-Pedersen protocol

    @abstractmethod
    def _chaum_pedersen_proof(self, ddh, z):
        """
        Implementation of Chaum-Pedersen protocol from the prover's side (non-interactive)

        Returns zero-knowledge proof that the provided 3-ple `ddh` is a DDH with respect
        to the generator g of the systemtem's underlying group, i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q
        """

    @abstractmethod
    def _chaum_pedersen_verify(self, ddh, proof):
        """
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Validates the demonstrated zero-knowledge `proof` that the provided 3-ple `ddh` is a
        DDH with respect to the generator g of the systemtem's underlying group, i.e., of
        the form
                                (u, v, g ^ (x * z) modp)

        where u = g ^ x modp, v = g ^ z modp with 0 <= x, z < q
        """

    # Digital Signature Algorithm

    @abstractmethod
    def _dsa_signature(self, exponent, private_key):
        """
        Applies (EC)DSA to compute the digital signature of the provided `exponent`
        under the given `private_key`
        """

    @abstractmethod
    def _dsa_verify(self, exponent, signature, public_key):
        """
        Verifies that the provded `signature` is the (EC)DSA-signature of the
        provided `exponent` under the given `public_key`
        """

    # El-Gamal encryption

    @abstractmethod
    def _encrypt(self, element, public_key, randomness=None):
        """
        Encrypts the provided algebraic element with the provided public key
        """
        pass

    @abstractmethod
    def _decrypt(self, ciphertext, private_key):
        """
        Decrypts the provided ciphertext with the given private key
        and returns the original
        """
        pass

    @abstractmethod
    def _prove_encryption(self, ciphertext, randomness):
        """
        Generates proof-of-knowledge of the provided randomness used in the
        encryption yielding the given ElGamal ciphertext
        """
        pass

    @abstractmethod
    def _verify_encryption(self, proof, ciphertext):
        """
        Verifies proof-of-knowledge of randomness used in the encryption yielding
        the provided ElGamal ciphertext
        """
        pass


# ------------------------------------------------------------------------------

    def create_zeus_keypair(self, zeus_secret_key=None):
        """
        Creates and returns a key pair for zeus

        :type zeus_secret_key: mpz
        :rtype: dict
        """
        zeus_keypair = self.keygen(zeus_secret_key)
        return zeus_keypair


    def _extract_public_shares(self, trustee_public_keys):
        """
        Extracts public keys of the provided trustees as group elements
        and returns them in a list

        :type trustee_public_keys: list
        :rtype: list
        """
        public_shares = [self._extract_value(public_key)\
            for public_key in trustee_public_keys]
        return public_shares


    def compute_election_key(self, trustee_public_keys, zeus_keypair):
        """
        Computes and returns the election public key

        :type trustees: list
        :type zeus_keypair: dict
        :rtype: GroupElement
        """
        public_shares = self._extract_public_shares(trustee_public_keys)    # group elements
        zeus_public_key = self._extract_public_value(zeus_keypair)
        combined = self._combine_public_keys(zeus_public_key, public_shares)
        election_key = self._set_public_key_from_element(combined)
        return election_key  # proof: None


    def validate_election_key(self, election_key, trustee_keys,
                                zeus_keypair):
        """
        :type election_key: dict
        :type trustee_keys: list
        :type zeus_keypair: dict
        :rtype: bool
        """
        election_key = self._extract_value(election_key)
        test_key = self.compute_election_key()



# ------------------------------------------------------------------------------

    @abstractmethod
    def _combine_public_keys(self, initial, public_keys):
        """
        :type initial: GroupElement
        :type public_keys: list
        :rtype: GroupElement
        """


    def _set_vote(self, voter, encrypted, fingerprint,
                  audit_code=None, publish=None, voter_secret=None,
                  previous=None, index=None, status=None, plaintext=None):
        """
        """

        vote = {
            'voter': str(voter),
            'encrypted': encrypted,
            'fingerprint': hash_decode(fingerprint)
        }

        if audit_code:
            vote['audit_code'] = int(audit_code)
        if publish:
            vote['voter_secret'] = str(voter_secret)    # str(int(voter_secret))
        if previous:
            vote['index'] = str(index)
        if status:
            vote['status'] = status
        if plaintext:
            vote['plaintext'] = str(plaintext)

        return vote


    def _extract_vote(self, vote):
        """
        """
        voter = vote['voter']
        encrypted = vote['encrypted']
        fingerprint = hash_encode(vote['fingerprint'])

        audit_code = extract_value(vote, 'audit_code', int)
        voter_secret = extract_value(vote, 'voter_secret', int)

        previous = None
        if 'previous' in vote.keys():
            previous = hash_encode(vote['previous'])

        index = extract_value(vote, 'index', int)

        # plaintext is string?
        #
        # plaintext = mpz(extract_value(vote, 'plaintext', int))
        # plaintext = self.GroupElement(plaintext)
        #
        plaintext = extract_value(vote, 'plaintext', self.GroupElement)

        return voter, encrypted, fingerprint, audit_code,\
            voter_secret, previous, index, status, plaintext
