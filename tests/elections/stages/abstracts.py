from abc import ABCMeta, abstractmethod
import unittest
from tests.elections.stages.utils import create_election

def get_cls_name(obj): return obj.__class__.__name__


class StageTester(metaclass=ABCMeta):
    """
    Abstract testing frame for isolated election stages. By "current stage"
    is meant the stage under testing

        - Implement functions starting with test_* in order to test isolated
          functionalities of the current stage
        - Implement functions starting with step_* in alphabetical order
          for the purposes of overall stage testing
    """

    def launch_election(self):
        """
        Create and launch the election running in background
        """
        election = create_election()
        self.election = election

    @abstractmethod
    def run_until_stage(self):
        """
        Manually run in correct order all stages previous to the current one.
        After that, set the attribute .stage equal to the current one
        """

    def get_context(self):
        """
        Returns the context of all tests: running election, election config and
        current stage
        """
        election = self.election
        config = self.election.config
        stage = self.stage

        return election, config, stage

    def setUp(self):
        """
        Executed before every test execution
        """
        self.run_until_stage()
        self.messages = []

    def append_message(self, message):
        """
        Stores messages to be printed after every single test execution
        """
        self.messages.append(message)

    def tearDown(self):
        """
        Executed after every test execution
        """
        if self.messages:
            for i, message in enumerate(self.messages):
                if i == 0:
                    print('\n' + message)
                else:
                    print(message)

    def stage_steps(self):
        """
        Iterates alphabetically over attributes starting with step_*. These
        functions are meant to be the steps in respective order during
        overall stage testing (see the .test_run() function below)
        """
        for name in self.__dir__():
            if name.startswith('step_'):
                yield name, getattr(self, name)

    def step_0(self):
        election, _, stage = self.get_context()
        try:
            assert election._get_current_stage() is stage
            self.append_message('[+] Current stage: %s' % get_cls_name(stage))
        except AssertionError:
            err = "Wrong election stage"
            raise AssertionError(err)

    def test_run(self):
        """
        Overall stage testing

        Contrary to other functions starting with test_*, this one does not
        focus on specific functionalitites, running the stage from its
        beginning to the end.

        Implement functions starting with step_* in appropriate alphabetical
        order for the purposes of this test
        """
        print('\n')
        print('----------------------- Overall Stage Testing ------------------------')
        for name, step in self.stage_steps():
            try:
                step()
            except AssertionError as err:
                self.fail(f"\n\nFAIL: {name}: {err}")
