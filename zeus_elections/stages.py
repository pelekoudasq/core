from .abstracts import Stage, FinalStage

class Uninitialized(Stage):
    def run(self):
        print('Uninitialized')
    def next(self, input):
        return Creating(controller=self.controller)

class Creating(Stage):
    def run(self):
        print('Creating...')
    def next(self, input):
        return Voting(controller=self.controller)

class Voting(Stage):
    def run(self):
        print('Voting...')
    def next(self, input):
        return Mixing(controller=self.controller)

class Mixing(Stage):
    def run(self):
        print('Mixing...')
    def next(self, input):
        return Decrypting(controller=self.controller)

class Decrypting(Stage):
    def run(self):
        print('Decyrpting...')
    def next(self, input):
        return Finalized(controller=self.controller)

class Finalized(FinalStage):
    def run(self):
        print('Finalized')

class Broken(FinalStage):
    def run(self):
        print('BROKEN')
