"""
"""
import json

from clients import Trustee
from zeus_core.crypto import mk_cryptosys


class TrusteeEmulator(Trustee):
    """
    """
    trustee_secrets = 'tests/election/emulators/clients/trustee-secrets.json'
    trustee_publics = 'tests/election/emulators/trustees.json'


    def __init__(self, public):
        """
        """
        self.public = public


    def load_keypair_from_public(self):
        """
        """
        public = self.public
        public, proof, index = __class__.locate_trustee(public)
        private = __class__.locate_secret(index)
        public = self.set_public_key(public, proof)
        keypair = self.set_keypair(private, public)
        keypair = self.deserialize_keypair(keypair)
        self.store_keypair(keypair)


    @classmethod
    def locate_trustee(cls, public):
        """
        """
        with open(cls.trustee_publics) as __file:
            trustees = json.load(__file)
        index = cls.get_trustee_index(trustees, public)
        proof = trustees[index]['proof']
        return public, proof, index


    @classmethod
    def get_trustee_index(cls, trustees, public):
        """
        """
        nr_trustees = len(trustees)
        index = (i for i in range(nr_trustees) if \
                    trustees[i]['value'] == public).__next__()
        return index


    @classmethod
    def locate_secret(cls, index):
        """
        """
        with open(cls.trustee_secrets) as __file:
            trustee_secrets = json.load(__file)
        return trustee_secrets[index]


    # Communication

    def recv_crypto(self, crypto_config):
        """
        """
        cryptosys = mk_cryptosys(crypto_config)
        self.set_cryptosys(cryptosys)
        self.load_keypair_from_public()


    def recv_mixed_ballots(self, mixed_ballots):
        """
        """
        self.store_ciphers(mixed_ballots)
        self.generate_factor_colletion()


    def send_trustee_factors(self, election_server):
        """
        """
        factor_collection = self.get_factor_collection()
        serialized = self.serialize_factor_collection(factor_collection)
        return serialized
