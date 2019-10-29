"""
"""

from abc import ABCMeta, abstractmethod

def get_cls_name(obj): return obj.__class__.__name__


class StageTester(metaclass=ABCMeta):
    """
    Abstract testing frame for isolated election stages. By "current stage"
    is meant the stage under testing

        - Implement functions starting with test_* for the purpose of testing
          isolated funcitonalities of the current stage
        - Implement functions starting with step_* in alphabetical order
          for the purposes of overall stage testing
    """

    @classmethod
    def setUpClass(cls):
        cls.run_until_stage()
        cls.messages = []

    @classmethod
    @abstractmethod
    def run_until_stage(cls):
        """
        Create and load an election object as class attribute, then run it
        until the stage under testing and load the latter as class attribute
        """
        #
        # # Uncomment the following lines to implement a concrete subclass
        #
        # election = mk_election()
        # cls.election = election
        # # Run here successive stages until the stage to be tested
        # election.load_current_context()
        # cls.stage = election._get_current_stage()
        #

    @classmethod
    def tearDownClass(cls):
        messages = cls.messages
        for i, message in enumerate(messages):
            if i == 0:
                print('\n' + message)
            else:
                print(message)


    def get_context(self):
        """
        Returns the common context of all tests as a tuple:
        running election, election config and current stage
        """
        cls = self.__class__
        election = cls.election
        config = cls.election.config
        stage = cls.stage
        messages = cls.messages

        return election, config, stage, messages


    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)


    def stage_steps(self):
        """
        Iterates alphabetically over attributes starting with step_*. These
        functions are meant to be the steps performed successively during
        overall stage testing (see the .test_run() method below)
        """
        for name in self.__dir__():
            if name.startswith('step_'):
                yield name, getattr(self, name)


    def step_0(self):
        election, _, stage, messages = self.get_context()
        try:
            assert election._get_current_stage() is stage
            messages.append(f'[+] current stage: {get_cls_name(stage)}')
        except AssertionError:
            err = "Wrong election stage"
            raise AssertionError(err)


    def test_run(self):
        """
        Overall stage testing

        Run stage from its beginning to the end.

        Implement functions starting with step_* in appropriate alphabetical
        order to be ran successively during this test.
        """
        print('\n')
        print('----------------------- Overall Stage Testing ------------------------')
        for name, step in self.stage_steps():
            try:
                step()
            except AssertionError as err:
                self.fail(f"\n\nFAIL: {name}: {err}")
