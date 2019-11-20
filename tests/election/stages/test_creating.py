import pytest
import unittest
from copy import deepcopy
import time
import json

from zeus_core.election.constants import VOTER_SLOT_CEIL
from zeus_core.election.exceptions import (InvalidTrusteeError,
        InvalidCandidatesError, InvalidVotersError)

from tests.constants import _2048_SYSTEM, _2048_SECRET
from tests.election.utils import trim_json
from tests.election.makers import mk_election
from tests.election.stages.abstracts import StageTester, get_cls_name


class TestCreating(StageTester, unittest.TestCase):

    @classmethod
    def run_until_stage(cls):
        election = mk_election()
        cls.election = election
        election.run_until_creating_stage()
        cls.stage = election.get_current_stage()


    # Zeus keypair creation

    def test_create_zeus_keypair(self):
        election, _, creating, messages = self.get_context()
        cryptosys = election.get_cryptosys()
        election.create_zeus_keypair()
        zeus_keypair_1 = election.get_keypair()
        config = election.get_config()
        _, zeus_keypair_2 = _2048_SYSTEM.generate_keypair(config['zeus_private_key'])
        assert election.get_public_value(zeus_keypair_1) == zeus_keypair_2
        proof =  zeus_keypair_1['public']['proof']
        to_display = trim_json({
            'private': zeus_keypair_1['private'],
            'public': {
                'value': zeus_keypair_1['public']['value'].to_int(),
                'proof': {
                    'commitment': proof['commitment'].to_int(),
                    'challenge': int(proof['challenge']),
                    'response': int(proof['response']),
                }
            }
        })
        messages.append('[+] Successfully created: zeus_keypair: %s' %
            json.dumps(to_display, sort_keys=False, indent=4))


    # Trustees' validation

    def test_create_trustees(self):
        election, config, creating, messages = self.get_context()

        trustees = config['trustees']
        deserialized_trustees = election.deserialize_trustees(trustees)
        election.create_trustees()
        validated_trustees = election.get_trustees()
        expected_trustees = dict(((trustee['value'], trustee['proof'])
            for trustee in deserialized_trustees))
        assert validated_trustees == expected_trustees
        to_display = trim_json([{
            'value': public_key.to_int(),
            'proof': {
                'commitment': proof['commitment'].to_int(),
                'challenge': int(proof['challenge']),
                'response': int(proof['response']),
            }
        } for public_key, proof in validated_trustees.items()])
        messages.append('[+] Successfully created: trustees: %s' %
            json.dumps(to_display, sort_keys=False, indent=4))

    def test_validate_trustees_invalid_cases(self):
        election, config, creating, messages = self.get_context()

        trustees = config['trustees']
        corrupt_trustees = deepcopy(trustees)
        corrupt_trustees[0]['value'] += 1
        with self.assertRaises(InvalidTrusteeError):
            election.config['trustees'] = corrupt_trustees
            election.create_trustees()
        messages.append(f'[+] Successfully detected: Invalid trustee')


    # Election key computation

    def test_create_election_key(self):
        election, config, creating, messages = self.get_context()

        trustees = config['trustees']
        election_key_hex = \
        '8597626e19be0c87d1855beacbfa98dcdefa97d8decee3a4af961f89c5c6109d2d7ad2e' + \
        '4d866fda73969c82c4ff747a52730eb012760cadf494360da2b7c92e10d9d8519c63112' + \
        '2a95c91350997a29d37884399aeac2c7cc06d594abc861fbe4ecc0965734f9a2d2eaa7f' + \
        'a49b52840821f638dd02a05303555e92075988cf0c07917a8c6c76a1b91768fc090b446' + \
        'd5a80a3d69eceee042f9bc09e2bbf3c0ebd23b8483b4c9e7853abdec6a1f73be838792b' + \
        '0c6d8048552da292e4d08c2a9abce6a731fba79406e88ce70cf107701fb6c01182152a0' + \
        '49501445f5c39b712bba0cb1dfc45344e0289543fc6acd9021e857343bccf61b09ad9f6' + \
        'b2eb565ae0bf55d'
        election.create_zeus_keypair()
        zeus_keypair = election.get_keypair()
        election.create_trustees()
        validated_trustees = election.get_trustees()
        election.create_election_key()
        election_key = election.get_election_key()
        assert election_key.to_hex() == election_key_hex
        messages.append(f'[+] Successfully computed: election_key: {election_key_hex[:16]}...')


    # Candidates creation

    def test_create_candidates(self):
        election, config, creating, messages = self.get_context()

        candidates = config['candidates']
        election.create_candidates()
        assert candidates == election.get_candidates()
        messages.append('[+] Successfully created: candidates: %s' %
            json.dumps(candidates, sort_keys=False, indent=4))


    def mk_validate_candidates_abort_cases(self):
        election, config, _, _ = self.get_context()
        invalid_cases = [{
            'case': deepcopy(config['candidates']),
            'message': None
        } for _ in range(3)]
        invalid_cases[0]['case'][1] = invalid_cases[0]['case'][2]
        invalid_cases[0]['message'] = 'Duplicate candidate name'
        invalid_cases[1]['case'][1] += '%'
        invalid_cases[1]['message'] = "Invalid candidate name: '%' detected"
        invalid_cases[2]['case'][1] += '\n'
        invalid_cases[2]['message'] = "Invalid candidate name: '\\n' detected"
        return invalid_cases

    def test_validate_candidates_invalid_cases(self):
        election, _, creating, messages = self.get_context()

        invalid_cases = self.mk_validate_candidates_abort_cases()
        for abort_case in invalid_cases:
            candidates = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, candidates=candidates):
                election.config['candidates'] = candidates
                with self.assertRaises(InvalidCandidatesError):
                    election.create_candidates()
                messages.append(f'[+] Successfully aborted: {message}')

    # Votes and audit codes creation

    def test_create_voters_and_audit_codes(self):
        election, config, creating, messages = self.get_context()
        election.create_voters_and_audit_codes()
        new_voters = election.get_voters()
        audit_codes = election.get_audit_codes()
        inverse_voters = {voter: voter_key
            for voter_key, voter in new_voters.items()}
        get_audit_codes = lambda voter: audit_codes[inverse_voters[voter]]
        assert all(audit_codes[voter_key] == get_audit_codes(new_voters[voter_key])
            for voter_key in new_voters.keys())
        messages.append('[+] Successfully created: s and audit codes')


    def mk_create_voters_and_audit_codes_invalid_cases(self):
        election, config, _, _ = self.get_context()
        invalid_cases = [{
            'case': [deepcopy(config['voters']), VOTER_SLOT_CEIL],
            'message': None
        } for _ in range(3)]
        del invalid_cases[0]['case'][0][:]
        invalid_cases[0]['message'] = 'Zero number of voters'
        invalid_cases[1]['case'][0][0] = invalid_cases[1]['case'][0][1]
        invalid_cases[1]['message'] = 'Duplicate voter name'
        invalid_cases[2]['case'][1] = 1
        invalid_cases[2]['message'] = 'Insufficient slot variation'
        return invalid_cases

    def test_create_voters_and_audit_codes_invalid_cases(self):
        election, _, creating, messages = self.get_context()

        invalid_cases = self.mk_create_voters_and_audit_codes_invalid_cases()
        for abort_case in invalid_cases:
            voters, voter_slot_ceil = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, voters=voters, voter_slot_ceil=voter_slot_ceil):
                election.config['voters'] = voters
                with self.assertRaises(InvalidVotersError):
                    election.create_voters_and_audit_codes(voter_slot_ceil)
                messages.append(f'[+] Successfully aborted: {message}')


if __name__ == '__main__':
    print('\n================== Testing election stage: Creating ==================')
    time.sleep(.6)
    unittest.main()
