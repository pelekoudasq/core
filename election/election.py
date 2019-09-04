# ------------------------ State machine pattern

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

# ---------------------------- Zeus

class Uninitialized(Stage):
    def run(self):
        print('Uninitialized')
    def next(self, input):
        return Creating()

class Creating(Stage):
    def run(self):
        print('Creating...')
    def next(self, input):
        return Voting()

class Voting(Stage):
    def run(self):
        print('Voting...')
    def next(self, input):
        return Mixing()

class Mixing(Stage):
    def run(self):
        print('Mixing...')
    def next(self, input):
        return Decrypting()

class Decrypting(Stage):
    def run(self):
        print('Decyrpting...')
    def next(self, input):
        return Finalized()

class Finalized(FinalStage):
    def run(self):
        print('Finalized')

class Broken(FinalStage):
    def run(self):
        print('BROKEN')

class ZeusCoreElection(object):

    def __init__(self):
        self.stageController = StageController(initial_stage=Uninitialized())

    def run(self):
        self.stageController.run_all([0, 0, 0, 0, 0])


if __name__ == '__main__':
    ZeusCoreElection().run()
    # class Stage_0(Stage):
    #     def run(self):
    #         print('Stage 0')
    #     def next(self, input):
    #         if input == 0:
    #             return Stage_0()
    #         else:
    #             return Stage_1()
    # class Stage_1(Stage):
    #     def run(self):
    #         print('Stage 1')
    #     def next(self, input):
    #         if input == 1:
    #             return Stage_1()
    #         else:
    #             return Stage_2()
    # class Stage_2(FinalStage):
    #     def run(self):
    #         print('Stage 2')
    #         print('Process finished\n')
    #
    # StageController(initial_stage=Stage_0()).run_all([0, 1, 2])
