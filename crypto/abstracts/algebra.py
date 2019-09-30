from abc import ABCMeta, abstractmethod

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
    def __eq__(self):
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
    @abstractmethod
    def contained_in(self, group):
        """
        """

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
