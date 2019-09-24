from zeus_elections.abstracts import Stage
from .voting import Voting
from .finals import Aborted


class Creating(Stage):

    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=Voting)

    def _extract(self, input):
        zeus_private_key = None
        try:
            zeus_private_key = input['zeus_private_key']
        except KeyError:
            pass
        return (zeus_private_key,)

    def _set(self, zeus_private_key):
        self.zeus_private_key = zeus_private_key

    def _generate(self):
        election = self._get_controller()
        system = election.get_cryptosys()
        zeus_keypair = self._create_zeus_keypair(system, self.zeus_private_key)
        trustees = None
        candidates = None
        voters = None
        audit_codes = None

        return zeus_keypair, trustees, candidates, voters, audit_codes

    def _modify_controller(self, zeus_keypair, trustees, candidates, voters, audit_codes):
        election = self._get_controller()
        election.set_zeus_keypair(zeus_keypair)
        election.set_trustees(trustees)
        election.set_candidates(candidates)
        election.set_voters(voters)
        election.set_audit_codes(audit_codes)

        from time import sleep
        print('Creating...')
        sleep(.5)

    # ------

    def _create_zeus_keypair(self, system, zeus_private_key):
        zeus_keypair = system.keygen(zeus_private_key)
        return zeus_keypair

    def _create_trustees(self):
        # TODO: Implement
        return None
