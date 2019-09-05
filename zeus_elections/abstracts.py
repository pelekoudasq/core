from abc import ABCMeta, abstractmethod

class Stage(object, metaclass=ABCMeta):
    @abstractmethod
    def run(self):
        """
        """
    @abstractmethod
    def next(self, input):
        """
        """

class FinalStage(Stage, metaclass=ABCMeta):
    def next(self, input):
        return self

class StageController(object):
    def __init__(self, initial_stage):
        self.current_stage = initial_stage

    def run_all(self, inputs):
        self.current_stage.run()
        for input in inputs:
            self.current_stage = self.current_stage.next(input)
            self.current_stage.run()
