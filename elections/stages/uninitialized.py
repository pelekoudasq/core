from elections.abstracts import Stage, Abortion
from .creating import Creating

from crypto import make_crypto
from crypto.exceptions import AlgebraError, WrongCryptoError, WeakCryptoError
from mixnets import make_mixnet
from mixnets.exceptions import MixnetError


class Uninitialized(Stage):

    def __init__(self, controller):
        super().__init__(controller, next_stage_cls=Creating)

    def _extract_data(self, config):
        crypto_cls = config['crypto']['cls']
        crypto_config = config['crypto']['config']
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = config['mixnet']['config']

        return crypto_cls, crypto_config, mixnet_cls, mixnet_config

    def _generate(self, crypto_cls, crypto_config, mixnet_cls, mixnet_config):
        try:
            cryptosys = make_crypto(crypto_cls, crypto_config)
        except (AlgebraError, WrongCryptoError, WeakCryptoError) as err:
            raise Abortion(err)

        mixnet_config.update({'cryptosystem': cryptosys})
        try:
            mixnet = make_mixnet(mixnet_cls, mixnet_config)
        except MixnetError as err:
            raise Abortion(err)

        return cryptosys, mixnet

    def _update_controller(self, cryptosys, mixnet):
        election = self._get_controller()
        election.set_cryptosys(cryptosys)
        election.set_mixnet(mixnet)