from zeus_core.elections.stages import (Uninitialized, Creating, Voting,
    Mixing, Decrypting, Finalized)

def run_until_uninitialized_stage(election):
    uninitialized = Uninitialized(election)
    return uninitialized

def run_until_creating_stage(election):
    uninitialized = run_until_uninitialized_stage(election)
    uninitialized.run()
    creating = uninitialized.next()
    return creating

def run_until_voting_stage(election):
    creating = run_until_creating_stage(election)
    creating.run()
    voting = creating.next()
    return voting
