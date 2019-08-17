from abc import ABCMeta, abstractmethod
from .exceptions import WrongCryptoError, WeakCryptoError


class ElGamalCrypto(object, metaclass=ABCMeta):
    """
    Abstract class for ElGamal cryptosystems
    """

# -------------------------------- External API --------------------------------

    # Access

    @property
    @abstractmethod
    def system(self):
        """
        Returns a dictionary with the cryptosystem's parameters
        """

    @property
    @abstractmethod
    def group(self):
        """
        Returns the cryptosystem's underlying group
        """

    @abstractmethod
    def get_as_integer(self, public_key):
        """
        Returns the numerical value of the provided public key
        """

    # Key generation

    @abstractmethod
    def keygen(self, private_key=None, schnorr=True):
        """
        Generates a pair of a private and a public key, the latter
        accompanied by a proof-of-knowledge of the former
        """

    @abstractmethod
    def validate_key(self, public_key):
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
        to the generator g of the cryptosystem's underlying group, i.e., of the form

                        (g ^ x modp, g ^ z modp, g ^ (x * z) modp)

        for some integers 0 <= x, z < q
        """

    @abstractmethod
    def _chaum_pedersen_verify(self, ddh, proof):
        """
        Implementation of Chaum-Pedersen protocol from the verifier's side (non-interactive)

        Validates the demonstrated zero-knowledge `proof` that the provided 3-ple `ddh` is a
        DDH with respect to the generator g of the cryptosystem's underlying group, i.e., of
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
    def _decrypt(self, ciphertxt, private_key):
        """
        Decrypts the provided ciphertxt with the given private key
        and returns the original
        """
        pass

    @abstractmethod
    def _prove_encryption(self, ciphertxt, randomness):
        """
        Generates proof-of-knowledge of the provided randomness used in the
        ElGamal encryption yielding the given ciphertxt
        """
        pass

    # @abstractmethod
    # def __init__(self, cls, config, *opts):
    #     try:
    #         system = cls.generate_system(config)
    #     except WrongCryptoError:
    #         raise
    #
    #     try:
    #         cls.validate_system(system, *opts)
    #     except (WrongCryptoError, WeakCryptoError):
    #         raise
    #
    #     self._set_params(system)
