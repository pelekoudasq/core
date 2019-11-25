"""
"""

from abc import ABCMeta, abstractmethod
from .manager import FactorManager


class FactorGenerator(FactorManager, metaclass=ABCMeta):
    """
    Factor generation interface (for both zeus and trustees)
    """

    def store_ciphers(self, ciphers):
        """
        """
        self.ciphers = ciphers


    def get_ciphers(self):
        """
        """
        return self.ciphers


    def get_factor_collection(self):
        """
        """
        factor_collection = None
        try:
            factor_collection = self.factor_collection
        except AttributeError:
            pass
        return factor_collection


    def store_factor_collection(self, public, factors):
        """
        """
        factor_collection = self.set_factor_collection(public, factors)
        self.factor_collection = factor_collection


    def generate_factor_colletion(self, ciphers=None):
        """
        """
        keypair = self.get_keypair()
        private_key, public_key = self.extract_keypair(keypair)
        if ciphers is None:
            ciphers = self.get_ciphers()
        decryption_factors = self.compute_decryption_factors(private_key, ciphers)
        self.store_factor_collection(public_key, decryption_factors)


    def compute_decryption_factors(self, secret, ciphers):
        """
        Use the provided secret x to construct an acclaimed DDH tuple for each
        of the given ciphers and generate proof-of-knowledge that the produced
        tuple is DDH. Returns a list of these proofs along with the last member
        of the corresponding DDH.

        For each ciphertext

                            {'alpha': a, 'beta': ...}

        from the provided ciphers, assuming that

                                a = g ^ r (modp)

        as the result of ElGamal-encryption, generate a Chaum-Pedersen
        proof-of-knowledge s that the tuple

                g ^ r (modp), g ^ x (modp), g ^ (r * x) modp

        is DDH and return the list of pairs

                    {'data': g ^ (r * x) (modp), 'proof': s}

        :type secret: exponent
        :type ciphers: list[dict{'alpha': GroupElement, 'beta': GroupElement}]
        :rtype: list[dict{'data': GroupElement, 'proof': Chaum-Pedersen}]
        """
        cryptosys = self.get_cryptosys()

        public = cryptosys.group.generate(secret)                        # g ^ x         (mod p)

        factors = []
        append = factors.append
        for cipher in ciphers:

            alpha, _ = cryptosys.extract_ciphertext(cipher)              # g ^ r         (mod p)
            data = alpha ** secret                                       # g ^ (x * r)   (mod p)

            ddh = (alpha, public, data)

            proof = cryptosys._chaum_pedersen_proof(ddh, secret)
            factor = self.set_factor(data, proof)
            append(factor)

        return factors
