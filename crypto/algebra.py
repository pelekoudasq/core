from abc import ABCMeta, abstractmethod

class Group(object, metaclass=ABCMeta):

    @abstractmethod
    def __repr__(self):
        """
        """

    @abstractmethod
    def __hash__(self):
        """
        """

    @property
    @abstractmethod
    def order(self):
        """
        """

    @abstractmethod
    def contains(self, element):
        """
        """

class GroupElement(object, metaclass=ABCMeta):

    @abstractmethod
    def __repr__(self):
        """
        """

    @abstractmethod
    def __hash__(self):
        """
        """

    @abstractmethod
    def __mul__(self, other):
        """
        """

    @abstractmethod
    def __pow__(self, exp):
        """
        """

    @property
    @abstractmethod
    def inverse(self):
        """
        """
