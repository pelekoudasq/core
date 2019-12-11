"""
"""

from .exceptions import WrongMixnetError
from .zeus_sk import Zeus_SK

supported_mixnets = (Zeus_SK,)


def mk_mixnet(mixnet_config, election_key=None):
    """
    """
    cls = mixnet_config.pop('cls')
    if cls not in supported_mixnets:
        err = "Requested mixnet is not supported"
        raise WrongMixnetError(err)
    return cls(mixnet_config, election_key)
