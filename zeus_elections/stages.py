from .abstracts import Stage, FinalStage

from time import sleep

class Uninitialized(Stage):
    def run(self):
        print('Uninitialized')
        sleep(.5)
    def next(self, input):
        return Creating(controller=self.controller)

class Creating(Stage):
    def run(self):
        print('Creating...')
        sleep(.5)
    def next(self, input):
        return Voting(controller=self.controller)

class Voting(Stage):
    def run(self):
        print('Voting...')
        sleep(.5)
    def next(self, input):
        return Mixing(controller=self.controller)

class Mixing(Stage):
    def run(self):
        print('Mixing...')
        sleep(.5)
    def next(self, input):
        return Decrypting(controller=self.controller)

class Decrypting(Stage):
    def run(self):
        print('Decyrpting...')
        sleep(.5)
    def next(self, input):
        return Finalized(controller=self.controller)

class Finalized(FinalStage):
    def run(self):
        print('Finalized')
        sleep(.5)

class Broken(FinalStage):
    def run(self):
        print('BROKEN')
        sleep(.5)
