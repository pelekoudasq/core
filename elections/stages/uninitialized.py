from elections.abstracts import Stage
from .creating import Creating

from crypto import make_crypto
from mixnets import make_mixnet

class Uninitialized(Stage):

    def _extract_data(self):
        config = self._get_config()
        self.crypto_cls = config['crypto']['cls']
        self.crypto_config = config['crypto']['config']
        self.mixnet_cls = config['mixnet']['cls']
        self.mixnet_config = config['mixnet']['config']

    def _generate(self):
        cryptosys = make_crypto(self.crypto_cls, self.crypto_config)
        self.mixnet_config.update({'cryptosystem': cryptosys})
        mixnet = make_mixnet(self.mixnet_cls, self.mixnet_config)
        return cryptosys, mixnet

    def _modify_controller(self, cryptosys, mixnet):
        election = self._get_controller()
        election.set_cryptosys(cryptosys)
        election.set_mixnet(mixnet)

        from time import sleep
        print('Uninitialized...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        return Creating(controller=election)
