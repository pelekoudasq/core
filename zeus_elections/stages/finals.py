from zeus_elections.abstracts import FinalStage

from time import sleep


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


class Aborted(FinalStage):
    def run(self):
        print('Aborted')
        sleep(.5)

    def _make(self):
        pass

    def _extract(self, config):
        return []

    def _set(self, *extracted):
        pass
