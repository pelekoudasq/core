from abc import ABCMeta, abstractmethod
import warnings


class Stage(object, metaclass=ABCMeta):

    def __init__(self, controller):
        controller.stage = self
        self.controller = controller
        self._extract_data()

    def _get_controller(self):
        return self.controller

    def _get_config(self):
        controller = self._get_controller()
        return controller.get_config()

    def run(self):
        self._modify_controller(*self._generate())

    @abstractmethod
    def _extract_data(self):
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

    @abstractmethod
    def next(self):
        """
        """

class FinalStage(Stage, metaclass=ABCMeta):

    def next(self):
        return self
        

class StageController(object):

    def __init__(self, initial_cls, config):
        if not issubclass(initial_cls, Stage):
            raise AssertionError('No initial stage provided')
        self.config = config
        self.current_stage = initial_cls(self)

    def run(self):
        current_stage = self._get_current_stage()   # Initial stage
        current_stage.run()
        while not isinstance(current_stage, FinalStage):
            current_stage = current_stage.next()
            current_stage.run()

    def _get_current_stage(self):
        return self.current_stage

    def get_config(self):
        return self.config
