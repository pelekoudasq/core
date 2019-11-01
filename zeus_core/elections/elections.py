from abc import ABCMeta, abstractmethod
from itertools import repeat
from copy import deepcopy

from .abstracts import StageController, Aborted
from .stages import (Uninitialized, Creating, Voting, Mixing, Decrypting, Finished,)
from .validations import Validator
from .signatures import Signer
from .exceptions import Abortion


class GenericAPI(object):

    def get_cryptosys(self):
        return self.cryptosys

    def get_crypto_params(self):
        return self.crypto_params

    def get_mixnet(self):
        return self.mixnet

    def get_zeus_private_key(self):
        return self.zeus_private_key

    def get_zeus_public_key(self):
        return self.zeus_public_key

    def get_hex_zeus_public_key(self):
        return self.hex_zeus_public_key

    def get_trustees(self):
        return self.trustees

    def get_trustee(self, public_key):
        """
        """
        return self.trustees[public_key]

    def get_public_shares(self):
        """
        """
        trustees = self.trustees
        get_key_value = self.get_cryptosys().get_key_value
        public_shares = [get_key_value(public_key)
            for public_key in trustees.keys()]
        return public_shares

    def get_hex_trustee_keys(self):
        """
        Returns values of trustee public keys as a list of sorted hex strings
        """
        return self.hex_trustee_keys

    def get_election_key(self):
        return self.election_key

    def get_hex_election_key(self):
        return self.hex_election_key

    def get_candidates(self):
        return self.candidates

    def get_candidates_set(self):
        return self.candidates_set

    def get_voters(self):
        # return dict(self.voters)
        return self.voters

    def get_voter(self, voter_key):
        # voters = self.voters
        # if voter_key not in voters:
        #     return None
        # return voters[voter_key]
        return self.voters.get(voter_key)

    def get_audit_codes(self):
        # return dict(self.audit_codes)
        return self.audit_codes

    def get_voter_audit_codes(self, voter_key):
        # audit_codes = self.audit_codes
        # if voter_key not in audit_codes:
        #     return None
        # return audit_codes[voter_key]
        return self.audit_codes.get(voter_key)

    def get_audit_publications(self):
        # return list(self.audit_publications)
        return self.audit_publications

    def get_audit_requests(self):
        # return dict(self.audit_requests)
        return self.audit_requests

    def get_audit_request(self, fingerprint):
        # audit_requests = self.audit_requests
        # if fingerprint not in audit_requests:
        #     return None
        # return audit_requests[fingerprint]
        return self.audit_requests.get(fingerprint)

    def get_audit_votes(self):
        return self.audit_votes

    def get_votes(self):
        # return dict(self.votes)
        return self.votes

    def get_vote(self, fingerprint):
        return self.votes.get(fingerprint)

    # def do_get_vote_index(self):
    def get_cast_vote_index(self):
        # return list(self.cast_vote_index)
        return self.cast_vote_index

    # def do_get_index_vote(self, index):
    def get_cast_vote_from_index(self, index):
        """
        Retrieve a cast vote's fingerprint from its index.
        Returns None if requested index exceeds current
        length of cast vote index.
        """
        cast_vote_index = self.cast_vote_index
        if index >= len(cast_vote_index):
            return None
        return cast_vote_index[index]

    # def get_all_cast_votes(self):
    def get_cast_votes(self):
        # return dict(self.cast_votes)
        return self.cast_votes

    # def do_get_cast_votes(self, voter_key):
    def get_voter_cast_votes(self, voter_key):
        # cast_votes = self.cast_votes
        # if voter_key not in cast_votes:
        #     return None
        # return cast_votes[voter_key]
        return self.cast_votes.get(voter_key)

    def get_excluded_voters(self):
        # return dict(self.excluded_voters)
        return self.excluded_voters

    def do_get_last_mix(self):
        mixes = self.mixes
        return None if not mixes else mixes[-1]


class UninitializedAPI(object):

    def set_cryptosys(self, cryptosys):
        self.cryptosys = cryptosys
        self.crypto_params = self.cryptosys.parameters()

    def set_mixnet(self, mixnet):
        self.mixnet = mixnet


class CreatingAPI(object):

    def set_zeus_keypair(self, zeus_keypair):
        system = self.get_cryptosys()
        zeus_private_key, zeus_public_key = system.extract_keypair(zeus_keypair)
        self.zeus_private_key = zeus_private_key
        self.zeus_public_key = zeus_public_key
        self.zeus_keypair = zeus_keypair
        self.hex_zeus_public_key = zeus_public_key['value'].to_hex()

    def set_trustees(self, trustees):
        self.trustees = trustees
        self.hex_trustee_keys = list(public_key.to_hex()
            for public_key in trustees.keys())
        self.hex_trustee_keys.sort()

    def store_trustee(self, trustee):
        public_key = trustee['value']
        proof = trustee['proof']
        self.trustees[public_key] = proof

    def set_election_key(self, election_key):
        cryptosys = self.get_cryptosys()
        self.election_key = cryptosys.get_key_value(election_key)
        self.mixnet.set_election_key(self.election_key)
        self.hex_election_key = cryptosys.get_hex_value(self.election_key)

    def set_candidates(self, candidates):
        self.candidates = candidates
        self.candidates_set = set(self.candidates)

    def set_voters(self, voters):
        self.voters = voters

    def set_audit_codes(self, audit_codes):
        self.audit_codes = audit_codes


class VotingAPI(object):

    def store_audit_publication(self, fingerprint):
        self.audit_publications.append(fingerprint)

    def store_audit_request(self, fingerprint, voter_key):
        """
        Stores also the corresponding audit-vote!
        """
        self.audit_requests[fingerprint] = voter_key

    def do_index_vote(self, fingerprint):
        """
        Store a vote's fingerprint in cast vote index and return its index
        """
        cast_vote_index = self.cast_vote_index
        index = len(cast_vote_index)
        cast_vote_index.append(fingerprint)
        return index

    def store_votes(self, votes):
        for vote in votes:
            fingerprint = vote['fingerprint']
            self.votes[fingerprint] = vote

    def append_vote(self, voter_key, fingerprint):
        cast_votes = self.cast_votes
        if voter_key not in cast_votes:
            cast_votes[voter_key] = []
        cast_votes[voter_key].append(fingerprint)

    def store_audit_vote(self, vote):
        self.audit_votes['fingerprint'] = vote

    def store_excluded_voter(self, voter_key, reason):
        self.excluded_voters[voter_key] = reason


class MixingAPI(object):

    def store_mix(self, mix):
        self.mixes.append(mix)

class DecryptingAPI(object): pass
class FinishedAPI(object): pass
class AbortedAPI(object): pass


backend_apis = (GenericAPI, UninitializedAPI, CreatingAPI, VotingAPI,
    MixingAPI, DecryptingAPI, FinishedAPI, AbortedAPI,)

class ZeusCoreElection(StageController, *backend_apis, Validator, Signer, metaclass=ABCMeta):
    """
    """

    labels = {'UNINITIALIZED': Uninitialized,
              'CREATING': Creating,
              'VOTING': Voting,
              'MIXING': Mixing,
              'DECRYPTING': Decrypting,
              'FINISHED': Finished,
              'ABORTED': Aborted,}


    def __init__(self, config, **kwargs):
        """
        """
        self.config = self.extract_config(config)
        self.options = kwargs
        self.initialize_entities()
        super().__init__(Uninitialized)

    @staticmethod
    def extract_config(config):
        """
        """
        config = deepcopy(config)
        try:
            crypto = config['crypto']
            mixnet = config['mixnet']
            trustees = config['trustees']
            candidates = config['candidates']
            voters = config['voters']
        except KeyError as e:
            err = f'Incomplete election config: missing {e}'
            raise Abortion(err)
        config['crypto_cls'] = crypto['cls']
        config['crypto_config'] = crypto['config']
        config['mixnet_cls'] = mixnet['cls']
        config['mixnet_config'] = mixnet['config']
        del config['crypto']
        del config['mixnet']
        try:
            config['zeus_private_key']
        except KeyError:
            config['zeus_private_key'] = None
        return config

    def set_option(self, kwarg):
        """
        """
        self.options.update(kwarg)

    def get_option(self, key):
        """
        Returns None if the option doesn't exist
        """
        return self.options.get(key)

    def initialize_entities(self):
        """
        """

        # Modified during stage Uninitialized
        self.cryptosys = None
        self.crypto_params = {}
        self.mixnet = None

        # Modified during stage Creating
        self.zeus_keypair = None
        self.zeus_private_key = None
        self.zeus_public_key = None
        self.trustees = dict()
        self.election_key = None
        self.candidates = []
        self.voters = {}
        self.audit_codes = {}

        # Modified during stage Voting
        self.audit_requests = {}
        self.audit_votes = {}
        self.audit_publications = []
        self.cast_vote_index = []
        self.votes = {}
        self.cast_votes = {}
        self.excluded_voters = {}

        # Modified during stage Mixing
        self.mixes = []


    # Stage controller implementation

    @abstractmethod
    def load_submitted_votes(self):
        """
        """

    def load_data(self, stage):
        """
        """
        config = self.config
        stage_cls = stage.__class__
        data = ()

        if stage_cls is Uninitialized:
            crypto_cls = config['crypto_cls']
            crypto_config = config['crypto_config']
            mixnet_cls = config['mixnet_cls']
            mixnet_config = config['mixnet_config']
            data = (crypto_cls,
                    crypto_config,
                    mixnet_cls,
                    mixnet_config,)
        elif stage_cls is Creating:
            zeus_private_key = config['zeus_private_key']
            trustees = config['trustees']
            candidates = config['candidates']
            voters = config['voters']
            data = (zeus_private_key,
                    trustees,
                    candidates,
                    voters,)
        elif stage_cls is Voting:
            pass
        elif stage_cls is Mixing:
            votes_for_mixing, _ = self.extract_votes_for_mixing()
            data = (votes_for_mixing,)
        elif stage_cls is Decrypting:
            pass
        elif stage_cls is Finished:
            pass
        elif stage_cls is Aborted:
            pass

        return data

    def load_methods(self, stage):
        """
        """
        election = self
        cryptosys = self.get_cryptosys()
        mixnet = self.get_mixnet()

        stage_cls = stage.__class__
        functionalities = []

        if stage_cls is Uninitialized:
            pass
        elif stage_cls is Creating:
            functionalities.extend([
                election.store_trustee,
                cryptosys.keygen,
                cryptosys.get_key_value,
                cryptosys._get_public_value,
                cryptosys._combine_public_keys,
                cryptosys._set_public_key,
                cryptosys.validate_public_key,
                cryptosys.deserialize_trustees,
            ])
        elif stage_cls is Voting:
            pass
        elif stage_cls is Mixing:
            functionalities.extend([
                election.store_mix,
                election.do_get_last_mix,
                mixnet.mix_ciphers,
                mixnet.extract_header,
                mixnet.validate_mix,
            ])
        elif stage_cls is Decrypting:
            pass
        elif stage_cls is Finished:
            pass
        elif stage_cls is Aborted:
            pass

        for method in functionalities:
            setattr(stage, method.__name__, method)

    def update(self, *entities, stage):
        """
        """
        election = self
        stage_cls = stage.__class__

        if stage_cls is Uninitialized:
            cryptosys, mixnet = entities
            election.set_cryptosys(cryptosys)
            election.set_mixnet(mixnet)
        elif stage_cls is Creating:
            (zeus_keypair, trustees, election_key,
                candidates, voters, audit_codes) = entities
            election.set_zeus_keypair(zeus_keypair)
            election.set_trustees(trustees)
            election.set_election_key(election_key)
            election.set_candidates(candidates)
            election.set_voters(voters)
            election.set_audit_codes(audit_codes)
        elif stage_cls is Voting:
            # ~ No need for updates: running election individually updated
            # ~ with every new vote during execution of Voting._generate()
            pass
        elif stage_cls is Mixing:
            pass
        elif stage_cls is Decrypting:
            pass
        elif stage_cls is Finished:
            pass
        elif stage_cls is Aborted:
            pass


    def do_assert_stage(self, label):
        """
        """
        expected_stage_cls = self.__class__.labels[label.upper()]
        actual_stage_cls = self.current_stage.__class__
        if expected_stage_cls != actual_stage_cls:
            err = 'Election should be at stage %s, not %s' % (
                expected_stage_cls.__name__, actual_stage_cls.__name__)
            raise AssertionError(err)


    def invalidate_election_key():
        self.set_election_key(None)


    def exclude_voter(voter_key, reason=''):
        """
        """
        current_stage_cls = self._get_current_stage().__class__
        labels = self.__class__.labels
        if current_stage_cls in (labels[label] for label in
            ('Mixing', 'Decrypting', 'Finished',)):
            err = f'Cannot exclude voter at stage {current_stage_cls.__name__}'
        self.store_excluded_voter(voter_key, reason)


    def extract_votes_for_mixing(self):
        """
        Prepares input of Mixnet.mix_ciphers()
        """
        original_mix = {}
        original_mix.update({'header': self.mixnet.header})

        excluded_votes = set()
        excluded_voters = self.get_excluded_voters()
        update = excluded_votes.update
        get_cast_votes = self.get_cast_votes
        for voter_key, reason in excluded_voters.items():
            update(get_cast_votes(voter_key))

        cast_vote_index = self.get_cast_vote_index()
        get_voter = self.get_voter
        get_vote = self.get_vote
        vote_count = 0
        nr_votes = len(cast_vote_index)
        scratch = list([None]) * nr_votes
        counted = list([None]) * nr_votes
        for i, fingerprint in enumerate(cast_vote_index):
            vote = get_vote(fingerprint)
            index = vote['index']
            if i != index:
                err = f'Vote index mismatch {i} != {index}'
                raise AssertionError(err) # ----------------> Change exception ?
            if fingerprint in excluded_votes:
                continue
            voter_key = vote['voter']
            voter_name, voter_weight = get_voter(voter_key)
            enc_ballot = vote['encrypted_ballot']['ciphertext']
            _vote = (enc_ballot['alpha'], enc_ballot['beta'], voter_weight)
            scratch[i] = _vote
            counted[i] = fingerprint
            previous = vote['previous']
            if not previous:
                vote_count += 1
                continue
            previous_vote = get_vote(previous)
            previous_index = previous_vote['index']
            if previous_index >= index or scratch[previous_index] is None:
                err = 'Inconsistent index!'
                raise AssertionError(err) # ----------------> Change exception ?
            if previous_vote['voter'] != vote['voter']:
                err = f"Voter mismatch: {vote['voter']} vs {previous_vote['voter']}"
                raise AssertionError(err)
            scratch[previous_index] = None
            counted[previous_index] = None

        votes_for_mixing = []
        counted_list = []
        counted_votes = 0
        extend_votes_for_mixing = votes_for_mixing.extend
        extend_counted_list = counted_list.extend
        for c, v in zip(counted, scratch):
            if (c, v) == (None, None):
                continue
            elif None in (c, v):
                raise AssertionError() # -------------------> Change exception ?
            counted_votes += 1
            alpha, beta, weight = v
            vote = (alpha, beta)
            extend_votes_for_mixing(repeat(vote, weight))
            extend_counted_list(repeat(c, weight))
        if counted_votes != vote_count:
            err = f'Vote count mismatch: {counted_votes} != {vote_count}'
            raise AssertionError(err) # --------------------> Change exception ?
        original_mix.update({
            'original_ciphers': votes_for_mixing,
            'mixed_ciphers': votes_for_mixing,
        })
        return original_mix, counted_list


    # Individual trustee handling

    def reprove_trustee(public_key, proof):
        """
        """
        pass

    def add_trustee(public_key, proof):
        """
        """
        pass
