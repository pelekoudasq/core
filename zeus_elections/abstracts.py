from abc import ABCMeta, abstractmethod
import warnings
import logging

def log_warning(message, category=None, filename=None, lineno=None, file=None, line=None):
    logging.warning(' %s' % (message,))

class MissingInputError(BaseException):
    """
    """
    pass

class Stage(object, metaclass=ABCMeta):

    def __init__(self, controller):
        """
        """
        self.controller = controller

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
    def __init__(self, initial_cls):
        if not issubclass(initial_cls, Stage):
            raise AssertionError('No stage provided to start with')
        self.current_stage = initial_cls(self)
        self.__class__.configure_warning()


    @classmethod
    def configure_warning(cls):
        logging.basicConfig(level=logging.INFO)
        warnings.showwarning = log_warning


    def run_all(self, inputs):
        inputs = iter(inputs)

        self.current_stage.run()
        while not isinstance(self.current_stage, FinalStage):
            try:
                input = next(inputs)
            except StopIteration:
                raise MissingInputError('Not enough input')

            self.current_stage = self.current_stage.next(input)
            self.current_stage.run()

        try:
            extra_input = next(inputs)
        except StopIteration:
            pass                                                   # Normal case
        else:
            warnings.warn('There were extra inputs')
