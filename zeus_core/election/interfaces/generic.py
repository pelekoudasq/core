"""
"""

from copy import deepcopy

class GenericAPI(object):

    def set_option(self, kwarg):
        self.options.update(kwarg)

    def get_option(self, key):
        return self.options.get(key)

    def get_config(self):
        return deepcopy(self.config)

    def get_crypto_config(self):
        return self.config['crypto']

    def get_mixnet_config(self):
        config = self.config
        mixnet_cls = config['mixnet']['cls']
        mixnet_config = deepcopy(config['mixnet']['config'])
        cryptosys = self.get_cryptosys()
        mixnet_config.update({
            'cls': mixnet_cls,
            'cryptosys': cryptosys
        })
        return mixnet_config

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys
        self.crypto_params = cryptosys.parameters()

    def get_cryptosys(self):
        return self.cryptosys

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet

    def get_mixnet(self):
        return self.mixnet

    def get_crypto_params(self):
        return self.crypto_params

    def set_zeus_keypair(self, zeus_keypair):
        zeus_private_key, zeus_public_key = self.extract_keypair(zeus_keypair)
        self.zeus_private_key = zeus_private_key
        self.zeus_public_key = zeus_public_key
        self.zeus_keypair = zeus_keypair
        self.hex_zeus_public_key = zeus_public_key['value'].to_hex()

    def get_keypair(self):
        keypair = self.get_zeus_keypair()
        return keypair

    def get_zeus_keypair(self):
        zeus_keypair = {}
        zeus_keypair['private'] = self.zeus_private_key
        zeus_keypair['public'] = self.zeus_public_key
        return zeus_keypair

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def get_hex_zeus_public_key(self):
        return self.hex_zeus_public_key

    def set_trustees(self, trustees):
        self.trustees = trustees
        self.hex_trustee_keys = list(public_key.to_hex()
            for public_key in trustees.keys())
        self.hex_trustee_keys.sort()

    def get_trustees(self):
        return self.trustees

    def store_trustee(self, trustee):
        public_key = trustee['value']
        proof = trustee['proof']
        self.trustees[public_key] = proof

    def get_trustee(self, public_key):
        return self.trustees[public_key]

    def get_hex_trustee_keys(self):
        return self.hex_trustee_keys

    def set_election_key(self, election_key):
        cryptosys = self.get_cryptosys()
        self.election_key = self.get_key_value(election_key)
        self.mixnet.set_election_key(self.election_key)
        self.hex_election_key = self.get_hex_value(self.election_key)

    def get_election_key(self):
        return self.election_key

    def get_hex_election_key(self):
        return self.hex_election_key

    def invalidate_election_key():
        self.election_key = None
        self.hex_election_key = None

    def set_candidates(self, candidates):
        self.candidates = candidates
        self.candidates_set = set(self.candidates)

    def get_candidates(self):
        return self.candidates

    def get_candidates_set(self):
        return self.candidates_set

    def set_voters(self, voters):
        self.voters = voters

    def get_voters(self):
        return self.voters

    def get_voter(self, voter_key):
        return self.voters.get(voter_key)

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes

    def get_audit_codes(self):
        return self.audit_codes

    def get_voter_audit_codes(self, voter_key):
        return self.audit_codes.get(voter_key)

    def store_audit_publication(self, fingerprint):
        self.audit_publications.append(fingerprint)

    def get_audit_publications(self):
        return self.audit_publications

    def get_audit_requests(self):
        return self.audit_requests

    def store_audit_request(self, fingerprint, voter_key):
        self.audit_requests[fingerprint] = voter_key

    def get_audit_request(self, fingerprint):
        return self.audit_requests.get(fingerprint)

    def store_audit_vote(self, vote):
        self.audit_votes['fingerprint'] = vote

    def get_audit_votes(self):
        return self.audit_votes

    def append_vote(self, voter_key, fingerprint):
        cast_votes = self.cast_votes
        if voter_key not in cast_votes:
            cast_votes[voter_key] = []
        cast_votes[voter_key].append(fingerprint)

    def store_votes(self, votes):
        for vote in votes:
            fingerprint = vote['fingerprint']
            self.votes[fingerprint] = vote

    def get_votes(self):
        return self.votes

    def get_vote(self, fingerprint):
        return self.votes.get(fingerprint)

    def get_voter_cast_votes(self, voter_key):
        return self.cast_votes.get(voter_key, [])

    def get_cast_vote_index(self):
        return self.cast_vote_index

    def do_index_vote(self, fingerprint):
        cast_vote_index = self.cast_vote_index
        index = len(cast_vote_index)
        cast_vote_index.append(fingerprint)
        return index

    def get_cast_vote_from_index(self, index):
        cast_vote_index = self.cast_vote_index
        if index >= len(cast_vote_index):
            return None
        return cast_vote_index[index]

    def get_cast_votes(self):
        return self.cast_votes

    def store_excluded_voter(self, voter_key, reason):
        self.excluded_voters[voter_key] = reason

    def exclude_voter(voter_key, reason=''):
        self.store_excluded_voter(voter_key, reason)

    def get_excluded_voters(self):
        return self.excluded_voters

    def get_mixnet_header(self):
        return self.mixnet.header

    def store_mix(self, mix):
        self.mixes.append(mix)

    def do_get_last_mix(self):
        mixes = self.mixes
        return None if not mixes else mixes[-1]

    def get_mixed_ballots(self):
        last_mix = self.do_get_last_mix()
        if last_mix is None:
            return []
        mixed_ballots = last_mix['mixed_ciphers']
        mixed_ballots = list(map(
            lambda ballot: {'alpha': ballot[0], 'beta': ballot[1]},
            mixed_ballots
        ))
        return mixed_ballots

    def store_ciphers(ciphers):
        pass

    def get_ciphers(self):
        ciphers = self.get_mixed_ballots()
        return ciphers

    def store_trustee_factors(self, trustee_factors):
        public_key, factors = self.extract_factor_collection(trustee_factors)
        public_key = self.get_key_value(public_key)
        self.trustees_factors.update({
            public_key: factors
        })

    def get_all_factors(self):
        trustees_factors = list(self.trustees_factors.values()) # Includes zeus factors!
        return [[factor for factor in trustee_factors] for trustee_factors in trustees_factors]

    def store_results(self, results):
        self.results = results

    def get_results(self):
        return self.results
