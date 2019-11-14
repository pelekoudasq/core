"""
Contains standalone interfaces for factor management and ballot decryption
"""

from abc import ABCMeta, abstractmethod


    #####################################################################
    #                                                                   #
    #       By factor is meant a dictionary of the form                 #
    #                                                                   #
    #       {                                                           #
    #         'data': GroupElement,                                     #
    #         'proof': dict                                             #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'proof' is a Chaum-Pedersen-proof        #
    #                                                                   #
    #####################################################################

    #####################################################################
    #                                                                   #
    #       By trustee-factors is meant a dictionary of the form        #
    #                                                                   #
    #       {                                                           #
    #           'public': GroupElement,                                 #
    #           'factors': list[factor]                                 #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'public' is thought of as the            #
    #       trustee's public key                                        #
    #                                                                   #
    #####################################################################


class FactorGenerator(object, metaclass=ABCMeta):
    """
    Factor generation interface (both for zeus and trustees)
    """

    @abstractmethod
    def get_cryptosys():
        """
        """

    @abstractmethod
    def _get_keypair(self):
        """
        """

    def set_factor(self, element, proof):
        """
        """
        factor = {}
        factor['data'] = element
        factor['proof'] = proof
        return factor


    def set_trustee_factors(self, public, factors):
        """
        """
        trustee_factors = {}
        trustee_factors['public'] = public
        trustee_factors['factors'] = factors
        return trustee_factors


    def store_trustee_factors(self, trustee_factors):
        """
        """
        self.factors = trustee_factors


    def compute_trustee_factors(self, mixed_ballots, store=True):
        """
        """
        cryptosys = self.get_cryptosys()

        trustee_keypair = self._get_keypair()
        private, public = cryptosys.extract_keypair(trustee_keypair)
        factors = self.compute_decryption_factors(private, mixed_ballots)
        trustee_factors = self.set_trustee_factors(public, factors)
        if store:
            self.store_trustee_factors(trustee_factors)
        return trustee_factors


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


class FactorValidator(object, metaclass=ABCMeta):
    """
    Factor validation interface
    """

    @abstractmethod
    def get_cryptosys():
        """
        """

    def extract_trustee_factors(self, trustee_factors):
        """
        """
        public = trustee_factors['public']
        factors = trustee_factors['factors']
        return public, factors

    def extract_factor(self, factor):
        """
        """
        element = factor['data']
        proof = factor['proof']
        return element, proof


    def validate_trustee_factors(self, mixed_ballots, trustee_public, trustee_factors):
        """
        """
        cryptosys = self.get_cryptosys()

        _, decryption_factors = self.extract_trustee_factors(trustee_factors)

        # TODO: Delete this snipset in alterative version
        if not trustee_public or not trustee_factors:
            err = 'Malformed trustee factors'
            raise InvalidFactorError(err)

        trustee_public = cryptosys.get_key_value(trustee_public)

        if not self.verify_decryption_factors(trustee_public, mixed_ballots, decryption_factors):
            err = 'Invalid trustee factors'
            raise InvalidFactorError(err)

        return True


    def verify_decryption_factors(self, public, ciphers, factors):
        """
        Returns `True` iff all the provided cipher-factor pairs are
        successfully verified under the provided `public` y

        .. note:: `False` is returned if the number of ciphers is unequal
        to the number of factors

        For each ciphertext

                            {'alpha': a, 'beta': ...}

        from the provided `ciphers` and corresponding factor

                             {'data': c, 'proof': s}

        from the provided `factors`, the current cipher-factor pair will be
        verified iff the (Chaum-Pedersen-proof) proves knowledge that the tuple

                                    (a, y, c)

        is DDH.

        :type public: GroupElement
        :type ciphers: list[dict]
        :type factors: list[dict]
        :rtype: bool
        """
        cryptosys = self.get_cryptosys()

        if len(ciphers) != len(factors):
            return False

        for cipher, factor in zip(ciphers, factors):
            alpha, _ = cryptosys.extract_ciphertext(cipher)
            data, proof = self.extract_factor(factor)

            ddh = (alpha, public, data)
            if not cryptosys._chaum_pedersen_verify(ddh, proof):
                return False

        return True


class Decryptor(FactorGenerator, FactorValidator, metaclass=ABCMeta):
    """
    Mixed ballots decryption interface to election server
    """

    @abstractmethod
    def get_zeus_private_key(self):
        """
        """

    @abstractmethod
    def get_zeus_public_key(self):
        """
        """

    def compute_zeus_factors(self, mixed_ballots):
        """
        """
        zeus_private = self.get_zeus_private_key()
        zeus_public = self.get_zeus_public_key()
        zeus_factors = self.compute_decryption_factors(zeus_private, mixed_ballots)
        zeus_factors = self.set_trustee_factors(zeus_public, zeus_factors)
        return zeus_factors


    def decrypt_ballots(self, mixed_ballots, all_factors):
        """
        """
        cryptosys = self.get_cryptosys()

        plaintexts = []
        append = plaintexts.append

        decryption_factors = self.combine_decryption_factors(all_factors)
        for ballot, factor in zip(mixed_ballots, decryption_factors):
            #
            # decryption_factors:
            #
            #          |ballot_1   |ballot_2   |ballot_3   |.........
            # ---------|-----------------------------------|---------
            #     zeus |factor01   |factor02   |factor03   |.........
            # trustee1 |factor11   |factor12   |factor13   |.........
            # trustee2 |factor21   |factor22   |factor23   |.........
            # trustee3 |factor31   |factor32   |factor33   |.........
            # ---------|-----------------------------------|---------
            #          |factor_1   |factor_2   |factor_3   |.........
            #
            encoded = cryptosys._decrypt_with_decryptor(ballot, factor)
            append(encoded.to_int())

        return plaintexts


    def combine_decryption_factors(self, trustees_factors):
        """
        Componentwise multiplication

        Given a 2D iterable

                    [[f_11, ..., f_1n], ..., [f_m1, ... f_mn]]

        of group elements, computes and returns the 1D iterable

                    [f_11 * ... * f_m1, ..., f_1n * ... * f_mn]

        .. note:: Returns a non-sensical 0 if the provided collection comprises of
        empty iterables (including the case of the collection itself being empty)

        :type trustees_factors: list[list[{'data': GroupElement, 'proof': ...}]]
        :rtype: list[GroupElement]
        """
        if not trustees_factors or trustees_factors == [[]] * len(trustees_factors):
            return 0
        master_factors = []
        append = master_factors.append
        group = self.get_cryptosys().group
        for factors_column in zip(*trustees_factors):
            master_factor = group.unit
            for trustee_factor in factors_column:
                data, _ = self.extract_factor(trustee_factor)
                master_factor *= data
            append(master_factor)
        return master_factors
