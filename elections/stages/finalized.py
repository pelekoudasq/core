from elections.abstracts import FinalStage, Abortion


class Finalized(FinalStage):

    def _extract_data(self, config):
        from time import sleep
        print('Finalized...')
        sleep(.5)

        return ()

    def _generate(self, *data):
        return ()

    def _update_controller(self, *generated):
        pass
