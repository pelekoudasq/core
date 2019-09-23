from .abstracts import Stage, FinalStage

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

class Creating(Stage):

    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Voting)

    def run(self):
        election = self._get_controller()
        system = election.get_cryptosys()
        zeus_keypair, trustees, candidates, voters, audit_codes = self._make(system)
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_candidates(candidates)
        election.set_voters(voters)
        election.set_audit_codes(audit_codes)
        print('Creating...')
        sleep(.5)

    def _make(self, system):
        zeus_keypair = self.create_zeus_keypair(system, self.zeus_private_key)
        trustees = None
        candidates = None
        voters = None
        audit_codes = None

        return zeus_keypair, trustees, candidates, voters, audit_codes

    def _extract(self, input):
        zeus_private_key = None
        try:
            zeus_private_key = input['zeus_private_key']
        except KeyError:
            pass
        return (zeus_private_key,)

    def _set(self, zeus_private_key):
        self.zeus_private_key = zeus_private_key

    def create_zeus_keypair(self, system, zeus_private_key):
        zeus_keypair = system.keygen(zeus_private_key)
        return zeus_keypair

    def create_trustees(self):
        # TODO: Implement
        return None

class Voting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Mixing)

    def run(self):
        print('Voting...')
        sleep(.5)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass

class Mixing(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Decrypting)

    def run(self):
        print('Mixing...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        try:
            next_input = election._get_next_input()
        except StopIteration:
            raise
        return Decrypting(election, next_input)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass

class Decrypting(Stage):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Finalized)

    def run(self):
        print('Decyrpting...')
        sleep(.5)

    def next(self):
        election = self._get_controller()
        try:
            next_input = election._get_next_input()
        except StopIteration:
            raise
        return Finalized(election, next_input)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass

class Finalized(FinalStage):

    def run(self):
        print('Finalized')
        sleep(.5)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass


class Broken(FinalStage):
    def run(self):
        print('BROKEN')
        sleep(.5)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass
