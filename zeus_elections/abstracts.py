from abc import ABCMeta, abstractmethod
import warnings

class MissingInputError(BaseException):
    pass

class Stage(object, metaclass=ABCMeta):

    def __init__(self, controller, input, next_stage_cls):
        if not issubclass(next_stage_cls, Stage):
            raise AssertionError('No valid next stage provided')
        self.controller = controller
        controller.stage = self
        self.next_stage_cls = next_stage_cls
        self._extract_data(input)

    def _get_controller(self):
        return self.controller

    def _get_next_stage_cls(self):
        return self.next_stage_cls

    def run(self):
        self._modify_controller(*self._generate())

    def next(self):
        controller = self._get_controller()
        next_input = controller._get_next_input()
        NextStage = self._get_next_stage_cls()
        return NextStage(controller, next_input)

    @abstractmethod
    def _extract_data(self, input):
        """
        """

    @abstractmethod
    def _generate(self):
        """
        """

    @abstractmethod
    def _modify_controller(self, *generated):
        """
        """


class FinalStage(Stage, metaclass=ABCMeta):
    def __init__(self, controller, input):
        super().__init__(controller, input, next_stage_cls=self.__class__)

    def next(self, input):
        return self


class StageController(object):

    def __init__(self, initial_cls, inputs):
        if not issubclass(initial_cls, Stage):
            raise AssertionError('No initial stage provided')
        self.inputs = inputs
        self.current_stage = initial_cls(self, next(self.inputs))

    def run(self):
        current_stage = self._get_current_stage()
        current_stage.run()
        while not isinstance(current_stage, FinalStage):
            try:
                current_stage = current_stage.next()
            except StopIteration:
                raise MissingInputError('Not enough input')
            current_stage.run()


    # Generic backend API

    def _get_current_stage(self):
        return self.current_stage

    def _get_next_input(self):
        return next(self.inputs)
