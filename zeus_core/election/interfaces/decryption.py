"""
"""

from abc import ABCMeta, abstractmethod


class Decryptor(object, metaclass=ABCMeta):
    """
    """

    @abstractmethod
    def get_cryptosys(self):
        """
        """

    @abstractmethod
    def extract_factor(self):
        """
        """

    def decrypt_ciphers(self, ciphers, all_factors):
        """
        """
        cryptosys = self.get_cryptosys()
        decrypt_with_decryptor = cryptosys.decrypt_with_decryptor

        plaintexts = []
        append = plaintexts.append

        decryption_factors = self.combine_decryption_factors(all_factors)
        for cipher, factor in zip(ciphers, decryption_factors):
            #
            # decryption_factors:
            #
            #          |cipher_1   |cipher_2   |cipher_3   |.........
            # ---------|-----------------------------------|---------
            #     zeus |factor01   |factor02   |factor03   |.........
            # trustee1 |factor11   |factor12   |factor13   |.........
            # trustee2 |factor21   |factor22   |factor23   |.........
            # trustee3 |factor31   |factor32   |factor33   |.........
            # ---------|-----------------------------------|---------
            #          |factor_1   |factor_2   |factor_3   |.........
            #
            encoded = decrypt_with_decryptor(cipher, factor)
            append(encoded.to_int())

        return plaintexts


    def combine_decryption_factors(self, all_factors):
        """
        Componentwise multiplication

        Given a 2D iterable

                    [[f_11, ..., f_1n], ..., [f_m1, ... f_mn]]

        of group elements, computes and returns the 1D iterable

                    [f_11 * ... * f_m1, ..., f_1n * ... * f_mn]

        .. note:: Returns a non-sensical [] if the provided collection
        comprises of empty iterables (including the case of the
        collection itself being empty)
        """
        if not all_factors or all_factors == [[]] * len(all_factors):
            # ~ Return empty iterable for the case of zero many mixed
            # ~ votes, so that zip in cipher decryption works well
            return []
        master_factors = []
        append = master_factors.append
        extract_factor = self.extract_factor
        group = self.get_group()
        for factors_column in zip(*all_factors):
            master_factor = group.unit
            for factor in factors_column:
                data, _ = extract_factor(factor)
                master_factor *= data
            append(master_factor)
        return master_factors
