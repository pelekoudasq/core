"""
Defines design pattern to core election object: state-machine (without table)
"""

from abc import ABCMeta, abstractmethod
from .exceptions import Abortion


class StageController(object, metaclass=ABCMeta):
    """
    Implements the state-machine design pattern
    """

    def __init__(self, initial_cls):
        """
        """
        if not issubclass(initial_cls, Stage):
            err = "No initial state provided"
            raise TypeError(err)
        self.current_stage = initial_cls(self)


    def run(self):
        """
        """
        current_stage = self.get_current_stage()
        current_stage.run()
        while not isinstance(current_stage, FinalStage):
            current_stage = current_stage.next()
            current_stage.run()


    def get_current_stage(self):
        """
        """
        return self.current_stage


class Stage(object, metaclass=ABCMeta):
    """
    Abstract class for the machine's states
    """

    def __init__(self, controller, **kwargs):
        """
        """
        self.forward_controller(controller)
        message, next_stage_cls, next_stage_message = self.validate_stage(**kwargs)

        self.message = message
        self.next_stage_cls = next_stage_cls
        self.next_stage_message = next_stage_message


    def forward_controller(self, controller):
        """
        """
        controller.current_stage = self
        self.controller = controller


    @classmethod
    def validate_stage(cls, **kwargs):
        """
        """
        message = kwargs.get('message')
        try:
            next_stage_cls = kwargs['next_stage_cls']
        except KeyError:
            err = "Missing kwarg: 'next_stage_cls'"
            raise TypeError(err)
        if not issubclass(next_stage_cls, cls.__base__):
            err = "No valid next state specified"
            raise TypeError(err)
        next_stage_message = None

        return message, next_stage_cls, next_stage_message


    def get_controller(self):
        """
        """
        return self.controller


    def _get_message(self):
        """
        """
        return self.message


    def _get_next_stage_cls(self):
        """
        """
        return self.next_stage_cls


    def _set_next_stage_cls(self, next_stage_cls):
        """
        """
        self.next_stage_cls = next_stage_cls


    def _set_next_stage_message(self, message):
        """
        """
        self.next_stage_message = message


    def _get_next_stage_message(self):
        """
        """
        return self.next_stage_message


    @abstractmethod
    def run(self):
        """
        """

    def next(self):
        """
        """
        controller = self.get_controller()
        kwargs = {}
        message = self._get_next_stage_message()
        if message is not None:
            kwargs.update({'message': message})
        NextStage = self._get_next_stage_cls()
        return NextStage(controller, **kwargs)


    def abort(self, abort_message):
        """
        """
        self._set_next_stage_cls(Aborted)
        self._set_next_stage_message(abort_message)


class FinalStage(Stage, metaclass=ABCMeta):
    """
    Abstract class to the machine's final states. Final stages are
    characterized by the fact that their next stage is the stage itself.
    """

    def __init__(self, controller, **kwargs):
        """
        """
        super().__init__(controller, next_stage_cls=__class__, **kwargs)


    def next(self):
        """
        """
        return self


class Aborted(FinalStage):
    """
    """

    def __init__(self, controller, message):
        """
        """
        super().__init__(controller, message=message)


    def run(self):
        """
        """
        pass
