from elections.abstracts import FinalStage


class Finalized(FinalStage):

    def _extract_data(self):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Finalized')
        sleep(.5)


class Aborted(FinalStage):

    def _extract_data(self):
        pass

    def _generate(self):
        return []

    def _modify_controller(self, *generated):
        from time import sleep
        print('Aborted')
        sleep(.5)
