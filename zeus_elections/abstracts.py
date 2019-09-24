from abc import ABCMeta, abstractmethod
import warnings

class MissingInputError(BaseException):
    pass

class Stage(object, metaclass=ABCMeta):

    def __init__(self, controller, input, next_stage_cls):
        self._set(*self._extract(input))
        self.controller = controller
        controller.stage = self

        if not issubclass(next_stage_cls, Stage):
            raise AssertionError('No valid next stage provided')
        self.next_stage_cls = next_stage_cls

    def _get_controller(self):
        return self.controller

    def get_next_stage_cls(self):
        return self.next_stage_cls

    @abstractmethod
    def run(self):
        """
        """
        # Should call _make

    def next(self):
        controller = self._get_controller()
        next_input = controller._get_next_input()
        NextStage = self.get_next_stage_cls()
        return NextStage(controller, next_input)

    @abstractmethod
    def _make(self):
        """
        """
        # Should call _get_controller

    @abstractmethod
    def _extract(self, input):
        """
        """

    @abstractmethod
    def _set(self, *extracted):
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
        first_input = next(self.inputs)
        self.current_stage = initial_cls(self, first_input)

    def run(self):
        current_stage = self._get_current_stage()
        current_stage.run()
        while not isinstance(current_stage, FinalStage):
            try:
                current_stage = current_stage.next()
            except StopIteration:
                raise MissingInputError('Not enough input')
            current_stage.run()

        try:
            extra_input = self._get_next_input()
        except StopIteration:
            pass                                                   # Normal case
        else:
            warnings.warn('There were extra inputs')

    # Generic API

    def _get_current_stage(self):
        return self.current_stage

    def _get_next_input(self):
        return next(self.inputs)
