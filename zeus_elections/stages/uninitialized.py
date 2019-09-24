from zeus_elections.abstracts import Stage
from .creating import Creating


from crypto import make_crypto
from mixnets import make_mixnet

class Uninitialized(Stage):

    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Creating)

    def _extract_data(self, input):
        self.crypto_cls = input['crypto']['cls']
        self.crypto_config = input['crypto']['config']
        self.mixnet_cls = input['mixnet']['cls']
        self.mixnet_config = input['mixnet']['config']

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
