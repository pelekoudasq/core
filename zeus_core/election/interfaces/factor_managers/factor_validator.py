"""
"""

from abc import ABCMeta, abstractmethod
from zeus_core.election.exceptions import InvalidFactorError
from .manager import FactorManager


class FactorValidator(FactorManager, metaclass=ABCMeta):
    """
    Factor validation interface (only for zeus)
    """

    def validate_factor_collection(self, ciphers, factor_collection):
        """
        """
        sender, factors = self.extract_factor_collection(factor_collection)
        sender_public = self.get_key_value(sender)

        if not self.verify_decryption_factors(sender_public, ciphers, factors):
            err = "Decryption factors could not be verified"
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
        if len(ciphers) != len(factors):
            return False

        cryptosys = self.get_cryptosys()
        _chaum_pedersen_verify = cryptosys._chaum_pedersen_verify
        extract_ciphertext = cryptosys.extract_ciphertext
        extract_factor = self.extract_factor
        for cipher, factor in zip(ciphers, factors):
            alpha, _ = extract_ciphertext(cipher)
            data, proof = extract_factor(factor)
            ddh = (alpha, public, data)
            if not _chaum_pedersen_verify(ddh, proof):
                return False

        return True
