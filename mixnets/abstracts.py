from abc import ABCMeta, abstractmethod

class MixnetError(Exception):
    """
    """
    pass


class Mixnet(object, metaclass=ABCMeta):
    """
    Abstract class for mixnets
    """
