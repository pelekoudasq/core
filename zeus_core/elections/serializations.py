from abc import ABCMeta, abstractmethod

class Serializer(object, metaclass=ABCMeta):
    """
    Serialization/deserialization interface to election server
    """
