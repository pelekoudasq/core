from .abstracts import Stage, FinalStage

class Uninitialized(Stage):
    def run(self):
        print('Uninitialized')
    def next(self, input):
        return Creating()

class Creating(Stage):
    def run(self):
        print('Creating...')
    def next(self, input):
        return Voting()

class Voting(Stage):
    def run(self):
        print('Voting...')
    def next(self, input):
        return Mixing()

class Mixing(Stage):
    def run(self):
        print('Mixing...')
    def next(self, input):
        return Decrypting()

class Decrypting(Stage):
    def run(self):
        print('Decyrpting...')
    def next(self, input):
        return Finalized()

class Finalized(FinalStage):
    def run(self):
        print('Finalized')

class Broken(FinalStage):
    def run(self):
        print('BROKEN')
