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
        config   = cls.election.config
        stage    = cls.stage
        messages = cls.messages

        return election, config, stage, messages


    def __fail(self, err):
        self.__class__.messages.append(f'[-] {err}')
        self.fail(err)
