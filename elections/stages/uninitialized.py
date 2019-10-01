from elections.abstracts import Stage
from elections.exceptions import Abortion
from .creating import Creating

from crypto import make_crypto
from crypto.exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from mixnets import make_mixnet
from mixnets.exceptions import MixnetError


class Uninitialized(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Creating)

    def _extract_data(self, config):
        try:
            crypto_cls = config['crypto']['cls']
            crypto_config = config['crypto']['config']
            mixnet_cls = config['mixnet']['cls']
            mixnet_config = config['mixnet']['config']
        except KeyError as err:
            raise Abortion(err)

        return crypto_cls, crypto_config, mixnet_cls, mixnet_config

    def _generate(self, crypto_cls, crypto_config, mixnet_cls, mixnet_config):
        cryptosys = self.init_cryptosys(crypto_cls, crypto_config)
        mixnet = self.init_mixnet(mixnet_cls, mixnet_config, cryptosys)

        return cryptosys, mixnet

    def _update_controller(self, cryptosys, mixnet):
        election = self._get_controller()
        election.set_cryptosys(cryptosys)
        election.set_mixnet(mixnet)

    # ---------

    def init_cryptosys(self, crypto_cls, crypto_config):
        try:
            cryptosys = make_crypto(crypto_cls, crypto_config)
        except (AlgebraError, WrongCryptoError, WeakCryptoError) as err:
            raise Abortion(err)
        return cryptosys

    def init_mixnet(self, mixnet_cls, mixnet_config, cryptosys):
        mixnet_config.update({'cryptosys': cryptosys})
        try:
            mixnet = make_mixnet(mixnet_cls, mixnet_config)
        except MixnetError as err:
            raise Abortion(err)
        return mixnet
