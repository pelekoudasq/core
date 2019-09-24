from zeus_elections.abstracts import Stage
from .creating import Creating
from .finals import Aborted

from time import sleep

from crypto import make_crypto
from mixnets import make_mixnet

class Uninitialized(Stage):

    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Creating)

    def run(self):
        election = self._get_controller()
        cryptosys, mixnet = self._make()

        election.set_cryptosys(cryptosys)
        election.set_mixnet(mixnet)

        print('Uninitialized...')
        sleep(.5)

    def _make(self):
        cryptosys = make_crypto(self.crypto_cls, self.crypto_config)
        self.mixnet_config.update({'cryptosystem': cryptosys})
        mixnet = make_mixnet(self.mixnet_cls, self.mixnet_config)
        return cryptosys, mixnet

    def _extract(self, input):
        crypto_cls = input['crypto']['cls']
        crypto_config = input['crypto']['config']
        mixnet_cls = input['mixnet']['cls']
        mixnet_config = input['mixnet']['config']

        return (crypto_cls, crypto_config, mixnet_cls, mixnet_config)

    def _set(self, crypto_cls, crypto_config, mixnet_cls, mixnet_config):
        self.crypto_cls = crypto_cls
        self.crypto_config = crypto_config
        self.mixnet_cls = mixnet_cls
        self.mixnet_config = mixnet_config
