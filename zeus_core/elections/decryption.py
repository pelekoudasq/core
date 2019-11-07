"""
Contains standalone interface for mixed ballots decryption
"""

from abc import ABCMeta, abstractmethod


class Decryptor(object, metaclass=ABCMeta):
    """
    Mixed ballots decryption interface to election server
    """

    @abstractmethod
    def get_zeus_private_key(self):
        """
        """

    def compute_zeus_factors(self, mixed_ballots):
        """
        """
        zeus_private = self.get_zeus_private_key()
        zeus_factors = self.compute_decryption_factors(zeus_private, mixed_ballots)
        return zeus_factors

    def compute_trustee_factors(self, mixed_ballots, trustee_keypair):
        """
        """
        cryptosys = self.get_cryptosys()

        private, public = cryptosys.extract_keypair(trustee_keypair)
        factors = self.compute_decryption_factors(private, mixed_ballots)
        trustee_factors = self.set_trustee_factors(public, factors)
        return trustee_factors

    def decrypt_ballots(self, mixed_ballots, trustees_factors, zeus_factors):
        """
        """
        plaintexts = []
        append = plaintexts.append

        all_factors = [trustee_factors['factors'] for trustee_factors in trustees_factors]
        all_factors.append(zeus_factors)

        decryption_factors = self.combine_decryption_factors(all_factors)
        for ballot, factor in zip(mixed_ballots, decryption_factors):
            # decryption_factors:
            #          |ballot_1   |ballot_2   |ballot_3   |.........
            # ---------|-----------------------------------|---------
            #     zeus |factor01   |factor02   |factor03   |.........
            # trustee1 |factor11   |factor12   |factor13   |.........
            # trustee2 |factor21   |factor22   |factor23   |.........
            # trustee3 |factor31   |factor32   |factor33   |.........
            # ---------|-----------------------------------|---------
            #          |factor_1   |factor_2   |factor_3   |.........
            encoded = self._decrypt_with_decryptor(ballot, factor)
            append(encoded.to_int())

        return plaintexts

    # Internal crypto

    def compute_decryption_factors(self, secret, ciphers):
        """
        Use the provided secret x to construct an acclaimed DDH tuple for each
        of the given ciphers and generate presumed proof-of-knowledge that the
        produced tuple is DDH. Returns a list of these proofs along with the
        last member of the corresponding DDH.

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
            factor = cryptosys._set_factor(data, proof)
            append(factor)

        return factors

    def combine_decryption_factors(self, trustees_factors):
        """
        Componentwise multiplication

        Given a 2D structure

        [[f_11, ..., f_1n], ..., [f_m1, ... f_mn]]

        of group elements, computes and returns the list

        [f_11 * ... * f_m1, ..., f_1n * ... * f_mn]

        .. note:: Returns a non-sensical 0 if the provided collection comprises
        of empty lists (including the case that the collection itself is empty)

        :type trustees_factors: list[list[{'data': ModPrimeElement, 'proof': ...}]]
        :rtype: list[ModPrimeElement]
        """
        if not trustees_factors or trustees_factors == [[]] * len(trustees_factors):
            return 0

        master_factors = []
        append = master_factors.append

        for factors_column in zip(*trustees_factors):
            master_factor = self.__group.unit
            for trustee_factor in factors_column:
                data, _ = self._extract_factor(trustee_factor)
                master_factor *= data
            append(master_factor)

        return master_factors

    # Formats

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

    def set_trustee_factors(self, public, factors):
        """
        """
        trustee_factors = {}
        trustee_factors['public'] = public
        trustee_factors['factors'] = factors
        return trustee_factors

    def extract_trustee_factors(self, trustee_factors):
        """
        """
        public = trustee_factors['public']
        factors = trustee_factors['factors']
        return public, factors


    #####################################################################
    #                                                                   #
    #       By factor is meant a dictionary of the form                 #
    #                                                                   #
    #       {                                                           #
    #         'data': GroupElement,                                     #
    #         'proof': dict                                             #
    #       }                                                           #
    #                                                                   #
    #       where the value of 'proof' is usually a Schnorr-proof       #
    #                                                                   #
    #####################################################################

    def set_factor(self, element, proof):
        """
        """
        factor = {}
        factor['data'] = element
        factor['proof'] = proof
        return factor


    def extract_factor(self, factor):
        """
        """
        element = factor['data']
        proof = factor['proof']
        return element, proof


    # Testing ----> Transfer the following methods to tests/elections/test_decryption module

    def validate_trustee_factors(self, mixed_ballots, trustee_public, trustee_factors):
        """
        """
        # trustee_public, decryption_factors = self._extract_trustee_factors(trustee_factors)
        _, decryption_factors = self._extract_trustee_factors(trustee_factors)

        # Delete this snipset in alterative version
        if not trustee_public or not trustee_factors:
            err = 'Malformed trustee factors'
            raise InvalidFactorError(err)

        trustee_public = self.get_value(trustee_public)

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
        verified iff the (Shnorr-proof) s proves knowledge that the tuple

        (a, y, c)

        is a DDH

        :type public: ModPrimeElement
        :type ciphers: list[dict]
        :type factors: list[dict]
        :rtype: bool
        """
        if len(ciphers) != len(factors):
            return False

        for cipher, factor in zip(ciphers, factors):
            alpha, _ = self.extract_ciphertext(cipher)
            data, proof = self._extract_factor(factor)

            ddh = (alpha, public, data)
            if not self._chaum_pedersen_verify(ddh, proof):
                return False

        return True


    def validate_ballots_decryption(self, mixed_ballots, trustees_factors,
            public_shares, zeus_factors, zeus_public_key):
        """
        Mixed ballots: list[{'alpha': ModPrimeElement, 'beta': ModPrimeElement}]

        Public shares: list[ModPrimeElement] or list[{'public': ModPrimElement, 'proof': ...}]

        Trustees factors: list[{
            'public': ModPrimeElement or {'public': ModPrimeElement, 'proof': ...},
            'factors': list[{'data': ModPrimeElement, 'proof': dict}]
        }]

        Zeus factors: list[{'data': ModPrimeElement, 'proof': dict}]

        :type mixed_ballots: list[dict]
        :type trustees_factors: list[list[dict]]
        :type public_shares: list[ModPrimeElement]
        :type zeus_factors: list[dict]
        :type zeus_public_key: ModPrimeElement
        :rtype: boolean
        """
        # Lengths check
        if len(trustees_factors) is not len(public_shares):
            err = 'Unequal number of public shares and trustees'
            raise BallotDecryptionError(err)

        # Remove proofs from trustees' public keys
        aux_factors = {}
        for trustee_factors in trustees_factors:
            public, factors = self._extract_trustee_factors(trustee_factors)
            public = self.get_value(public)
            aux_factors[public] = factors
        trustees_factors = aux_factors

        # Verify trustees' factors
        for share in public_shares:
            trustee_public = self.get_value(share)
            try:
                trustee_factors = trustees_factors[trustee_public]
            except KeyError:
                err = 'Trustee mismatch with public shares'
                raise BallotDecryptionError(err)

            if not self.verify_decryption_factors(trustee_public, mixed_ballots, trustee_factors):
                err = 'Trustee\'s factors could not be verified'
                raise BallotDecryptionError(err)

        # Verify zeus's factors
        zeus_public_key = self.get_value(zeus_public_key)
        if not self.verify_decryption_factors(zeus_public_key, mixed_ballots, zeus_factors):
            err = 'Zeus\'s factors could not be verified'
            raise BallotDecryptionError(err)

        return True
