from .exceptions import MixnetError
from .zeus_sk import Zeus_sk

supported_mixnets = (Zeus_sk,)

def make_mixnet(cls, config, election_key=None):
    if cls not in supported_mixnets:
        raise MixnetError('Requested mixnet is not supported')
    return cls(config, election_key)
