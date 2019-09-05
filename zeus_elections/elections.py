from utils import _teller

from zeus_elections.abstracts import StageController
from zeus_elections.stages import Uninitialized

# from gmpy2 import mpz
# from .modprime import ModPrimeCrypto
#
# def _2048_crypto(private_key=_2048_SECRET):
#     """
#     :private_key: int
#     :rtype dict:
#     """
#     system = ModPrimeCrypto(modulus=_2048_PRIME, primitive=_2048_PRIMITIVE)
#     keypair = system.keygen(private_key)
#     return system, keypair

class ZeusCoreElection(object):

    def __init__(self, teller=_teller, **kw):
        # self.stageController = StageController(initial_stage=Uninitialized(controller=self))
        from zeus_elections.stages import Uninitialized
        self.stageController = StageController(initial_cls=object)

    def run(self):
        self.stageController.run_all([0, 0, 0, 0, 0])

if __name__ == '__main__':
    ZeusCoreElection().run()
