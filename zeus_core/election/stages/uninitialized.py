"""
"""

from zeus_core.crypto.exceptions import (AlgebraError, WeakCryptoError,
                                        WrongCryptoError)
from zeus_core.mixnets.exceptions import MixnetConstructionError
from zeus_core.election.pattern import Stage
from zeus_core.election.exceptions import Abortion
from .creating import Creating


class Uninitialized(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Creating)

    def run(self):
        election = self.get_controller()

        try:
            election.init_cryptosys()
            election.init_mixnet()
        except (AlgebraError, WeakCryptoError, WrongCryptoError,
            MixnetConstructionError) as err:
            raise Abortion(err)
