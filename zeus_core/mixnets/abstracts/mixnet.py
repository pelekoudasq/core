from abc import ABCMeta, abstractmethod

class Mixnet(object, metaclass=ABCMeta):
    """
    Abstract base class for mixnets
    """

    @abstractmethod
    def parameters(self):
        """
        """
