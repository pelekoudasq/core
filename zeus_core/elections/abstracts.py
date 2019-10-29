from abc import ABCMeta, abstractmethod
import warnings

from .exceptions import Abortion

class Stage(object, metaclass=ABCMeta):

    def __init__(self, controller, **kwargs):
        controller.current_stage = self
        self.controller = controller

        try:
            next_stage_cls = kwargs['next_stage_cls']
        except KeyError:
            err = "Missing keyword argument: 'next_stage_cls'"
            raise TypeError(err)
        if not issubclass(next_stage_cls, self.__class__.__base__):
            err = "No valid next stage specified"
            raise AssertionError(err)
        self.next_stage_cls = next_stage_cls

        try:
            message = kwargs['message']
        except KeyError:
            pass
        else:
            self.message = message

        self.next_stage_message = None

    def get_controller(self):
        return self.controller

    def _set_next_stage_cls(self, next_stage_cls):
        self.next_stage_cls = next_stage_cls

    def _get_next_stage_cls(self):
        return self.next_stage_cls

    def _get_message(self):
        try:
            message = self.message
        except AttributeError:
            return None
        return message

    def _set_next_stage_message(self, message):
        self.next_stage_message = message

    def _get_next_stage_message(self):
        return self.next_stage_message

    def abort(self, abort_message):
        self._set_next_stage_cls(Aborted)
        self._set_next_stage_message(abort_message)

    def run(self):
        # config = self.controller.get_config()
        controller = self.get_controller()              #
        try:
            # data = self._extract_data(config)
            __data = controller.load_current_context()  # Return configs AND attach methods...
        except Abortion as err:
            self.abort(err)
            return

        try:
            # entities = self._generate(*data)
            # __data = data                               # Remove finally this line
            __entities = self._generate(*__data)
        except Abortion as err:
            self.abort(err)
            return

        # self._update_controller(*entities)
        controller.update(*__entities, stage=self)   #

    def next(self):
        controller = self.get_controller()
        kwargs = {}
        message = self._get_next_stage_message()
        if message is not None:
            kwargs.update({'message': message})
        NextStage = self._get_next_stage_cls()
        return NextStage(controller, **kwargs)

    # @abstractmethod
    # def _extract_data(self, config):
    #     """
    #     """

    @abstractmethod
    def _generate(self, *data):
        """
        """
        # Must return iterable

    # @abstractmethod
    # def _update_controller(self, *generated):
    #     """
    #     """

class FinalStage(Stage, metaclass=ABCMeta):

    def __init__(self, controller, **kwargs):
        super().__init__(controller, next_stage_cls=self.__class__, **kwargs)

    def next(self):
        return self

class Aborted(FinalStage):

    def __init__(self, controller, message):
        super().__init__(controller, message=message)

    def _extract_data(self, config):
        return ()

    def _generate(self, *data):
        return ()

    def _update_controller(self, *generated):
        print('sorry...:', self._get_message())


class StageController(object, metaclass=ABCMeta):

    def __init__(self, initial_cls, config):
        if not issubclass(initial_cls, Stage):
            err = "No initial stage provided"
            raise AssertionError(err)
        self.config = config
        self.current_stage = initial_cls(self)

    def run(self):
        from time import sleep
        current_stage = self._get_current_stage()   # Initial stage
        current_stage.run()
        print(self._get_current_stage().__class__.__name__)
        sleep(.5)
        while not isinstance(current_stage, FinalStage):
            current_stage = current_stage.next()
            current_stage.run()
            print(self._get_current_stage().__class__.__name__)
            sleep(.5)

    def _get_current_stage(self):
        return self.current_stage

    def get_config(self):
        return self.config

# ------------------------

    def load_current_context(self):
        """
        Must return iterable
        1. Load data (from election config
            or corresponding backend API)
        2. Load methods (attach methods from election
            or underlying crypto or underlying mixnet
        3. Return data for elaboration
        """
        current_stage = self._get_current_stage()

        data = self.load_data(current_stage)
        self.load_methods(current_stage)

        return data

    @abstractmethod
    def load_data(self, stage):
        """
        """

    @abstractmethod
    def load_methods(self, stage):
        """
        """

    @abstractmethod
    def update(self, *entities, stage):
        """
        """
