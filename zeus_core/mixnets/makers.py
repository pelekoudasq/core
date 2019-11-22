from .exceptions import WrongMixnetError
from .zeus_sk import Zeus_sk

supported_mixnets = (Zeus_sk,)


def mk_mixnet(mixnet_config, election_key=None):
    """
    """
    cls = mixnet_config.pop('cls')
    if cls not in supported_mixnets:
        raise WrongMixnetError('Requested mixnet is not supported')
    return cls(mixnet_config, election_key)
