from abc import ABCMeta, abstractmethod
import unittest

from tests.elections.stages.utils import create_election

class StageTester(metaclass=ABCMeta):

    def launch_election(self):
        election = create_election()
        self.election = election

    @abstractmethod
    def run_until_stage(self):
        """
        """
        pass

    def setUp(self):
        self.run_until_stage()
        self.messages = []

    def tearDown(self):
        if self.messages:
            for i, message in enumerate(self.messages):
                if i == 0:
                    print('\n' + message)
                else:
                    print(message)

    def stage_steps(self):
        for name in self.__dir__():
            if name.startswith('step_'):
                yield name, getattr(self, name)

    def test_run(self):
        print('\n')
        print('----------------------------- Run stage ------------------------------')
        for name, step in self.stage_steps():
            try:
                step()
            except AssertionError as err:
                self.fail("\n\nFAIL: {}: {}".format(name, err))
