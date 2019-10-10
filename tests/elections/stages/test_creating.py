import time
import pytest
from copy import deepcopy
import json

from tests.elections.stages.abstracts import StageTester, get_cls_name

from tests.constants import _2048_SYSTEM, _2048_SECRET
from tests.elections.stages.utils import create_election, run_until_creating_stage

from zeus_core.elections.stages import Uninitialized

from zeus_core.elections.constants import VOTER_SLOT_CEIL
from zeus_core.elections.exceptions import Abortion

import unittest

class TestCreating(StageTester, unittest.TestCase):

    # Common context implementation

    def run_until_stage(self):
        self.launch_election()
        uninitialized = Uninitialized(self.election)
        uninitialized.run()
        creating = uninitialized.next()
        self.stage = creating

    # ------------------------- Isolated funtionalities ------------------------

    # Zeus keypair creation

    def test_create_zeus_keypair(self):
        election, _, creating = self.get_context()

        cryptosys = election.get_cryptosys()
        zeus_keypair_1 = creating.create_zeus_keypair(_2048_SECRET)
        zeus_keypair_2 = _2048_SYSTEM.keygen(_2048_SECRET)
        assert cryptosys._get_public_value(zeus_keypair_1) == \
            _2048_SYSTEM._get_public_value(zeus_keypair_2)
        private = zeus_keypair_1['private']
        public = zeus_keypair_1['public']['value'].value
        proof =  zeus_keypair_1['public']['proof']
        serialized = {
            'private': '%s...' % ('%x' % private)[:16],
            'public': {
                'value': '%s...' % ('%x' % public)[:16],
                'proof': {
                    'commitment': '%s...' % ('%x' % proof['commitment'].value)[:16],
                    'challenge': '%s...' % ('%x' % proof['challenge'])[:16],
                    'response': '%s...' % ('%x' % proof['response'])[:16],
                }
            }
        }
        self.append_message('[+] Successfully created: zeus_keypair: %s'
            % json.dumps(serialized, sort_keys=False, indent=4))

    def test_create_zeus_keypair_abort_cases(self):
        _, _, creating = self.get_context()

        with self.assertRaises(Abortion): creating.create_zeus_keypair(1)
        self.append_message('[+] Successfully aborted: Small private key')


    # Trustees' validation

    def test_validate_trustees(self):
        _, config, creating = self.get_context()

        trustees = config['trustees']
        validated_trustees = creating.validate_trustees(trustees)
        assert validated_trustees == creating.deserialize_trustees(trustees)
        serialized = [{
            'value': '%s...' % ('%x' % trustee['value'].value)[:16],
            'proof': {
                'commitment': '%s...' % ('%x' % trustee['proof']['commitment'].value)[:16],
                'challenge': '%s...' % ('%x' % trustee['proof']['challenge'])[:16],
                'response': '%s...' % ('%x' % trustee['proof']['response'])[:16],
            }
        } for trustee in validated_trustees]
        self.append_message('[+] Successfully created: trustees: %s'
            % json.dumps(serialized, sort_keys=False, indent=4))

    def test_validate_trustees_abort_cases(self):
        _, config, creating = self.get_context()

        trustees = config['trustees']
        corrupt_trustees = deepcopy(trustees)
        corrupt_trustees[0]['value'] += 1
        with self.assertRaises(Abortion):
            creating.validate_trustees(corrupt_trustees)


    # Election key computation

    def test_compute_election_key(self):
        _, config, creating = self.get_context()

        trustees = config['trustees']
        election_key_hex = \
        '75142c805b7ba32068e48293d711e78fdbc8ff3bd6c080337d409554bb50287cb73e6eb' + \
        '56924ea287aa7902ecc3169f275e4ccf8cd9ead105f1c3907e81cdf16f7b6d5ab34afb6' + \
        'fdbcd41b4dd6c9172935d8e41a725dac0f308c6ea755d936e258f33127f976a2dcbe7d2' + \
        '5fdc001bae7847bd29b2c0448cc4fae1fba892d327667218836cd30a09a5f903dacab7d' + \
        '323b786898b77d3bc4ba117630749ebb9b8b061b320e67c3d8cd19d9ac34332eb909a49' + \
        '873510414c0fb15e8872c3dfec2ef9bdc5c72e35cdeb6216465967e7f725feefa55ea91' + \
        '86debb96d7aceefc480915f1f569283239efbbe058a72f1dcbfdec33149fcdfaddb5170' + \
        'a7f7ac0d81e51c8'
        zeus_keypair = creating.create_zeus_keypair(_2048_SECRET)
        validated_trustees = creating.validate_trustees(trustees)
        election_key = creating.compute_election_key(validated_trustees, zeus_keypair)
        assert election_key['value'].to_hex() == election_key_hex and \
            election_key['proof'] == None
        self.append_message('[+] Successfully computed: election_key: %s...'
            % election_key['value'].to_hex()[:16])


    # Candidates creation

    def test_create_candidates(self):
        _, config, creating = self.get_context()

        candidates = config['candidates']
        assert candidates == creating.create_candidates(candidates)
        self.append_message('[+] Successfully created: candidates: %s'
            % json.dumps(candidates, sort_keys=False, indent=4))

    def mk_create_candidates_abort_cases(self):
        _, config, _ = self.get_context()

        abort_cases = [{
            'case': deepcopy(config['candidates']),
            'message': None
        } for _ in range(3)]

        abort_cases[0]['case'][1] = abort_cases[0]['case'][2]
        abort_cases[0]['message'] = 'Duplicate candidate name'

        abort_cases[1]['case'][1] += '%'
        abort_cases[1]['message'] = "Invalid candidate name: '%' detected"

        abort_cases[2]['case'][1] += '\n'
        abort_cases[2]['message'] = "Invalid candidate name: '\\n' detected"

        return abort_cases

    def test_create_candidates_abort_cases(self):
        _, _, creating = self.get_context()

        abort_cases = self.mk_create_candidates_abort_cases()
        for abort_case in abort_cases:
            candidates = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, candidates=candidates):
                with self.assertRaises(Abortion):
                    creating.create_candidates(candidates)
                self.append_message('[+] Successfully aborted: %s' % message)

    # Voters and audit codes creation

    def test_create_voters_and_audit_codes(self):
        _, config, creating = self.get_context()

        new_voters, audit_codes = creating.create_voters_and_audit_codes(config['voters'])
        inverse_voters = {voter: voter_key
            for voter_key, voter in new_voters.items()}
        get_audit_codes = lambda voter: audit_codes[inverse_voters[voter]]
        assert all(audit_codes[voter_key] == get_audit_codes(new_voters[voter_key])
            for voter_key in new_voters.keys())
        self.append_message('[+] Successfully created: Voters and audit codes')

    def mk_create_voters_and_audit_codes_abort_cases(self):
        _, config, _ = self.get_context()

        abort_cases = [{
            'case': [deepcopy(config['voters']), VOTER_SLOT_CEIL],
            'message': None
        } for _ in range(3)]

        del abort_cases[0]['case'][0][:]
        abort_cases[0]['message'] = 'Zero number of voters'

        abort_cases[1]['case'][0][0] = abort_cases[1]['case'][0][1]
        abort_cases[1]['message'] = 'Duplicate voter name'

        abort_cases[2]['case'][1] = 1
        abort_cases[2]['message'] = 'Insufficient slot variation'

        return abort_cases

    def test_create_voters_and_audit_codes_abort_cases(self):
        _, _, creating = self.get_context()

        abort_cases = self.mk_create_voters_and_audit_codes_abort_cases()
        for abort_case in abort_cases:
            voters, voter_slot_ceil = abort_case['case']
            message = abort_case['message']
            with self.subTest(message, voters=voters, voter_slot_ceil=voter_slot_ceil):
                with self.assertRaises(Abortion):
                    creating.create_voters_and_audit_codes(voters, voter_slot_ceil)
                self.append_message('[+] Successfully aborted: %s' % message)


    # ------------------------- Overall stage testing --------------------------

    def step_1(self):
        election, _, _ = self.get_context()
        self.append_message('\nBefore running:\n')

        zeus_private_key = election.get_zeus_private_key()
        awaited = None
        try:
            assert zeus_private_key == awaited
            self.append_message('[+] zeus_private_key: %s' % zeus_private_key)
        except AssertionError:
            err = "Zeus private key was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        zeus_public_key = election.get_zeus_public_key()
        awaited = None
        try:
            assert zeus_public_key == awaited
            self.append_message('[+] zeus_public_key: %s' % zeus_public_key)
        except AssertionError:
            err = "Zeus public key was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        trustees = election.get_trustees()
        awaited = {}
        try:
            assert trustees == awaited
            self.append_message('[+] trustees: %s' % trustees)
        except AssertionError:
            err = "Trustees were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        election_key = election.get_election_key()
        awaited = None
        try:
            assert election_key == awaited
            self.append_message('[+] election_key: %s' % election_key)
        except AssertionError:
            err = "Zeus public key was not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        candidates = election.get_candidates()
        awaited = []
        try:
            assert candidates == awaited
            self.append_message('[+] candidates: %s' % candidates)
        except AssertionError:
            err = "Candidates were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        voters = election.get_voters()
        awaited = {}
        try:
            assert voters == awaited
            self.append_message('[+] voters: %s' % voters)
        except AssertionError:
            err = "Voters were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        audit_codes = election.get_audit_codes()
        awaited = {}
        try:
            assert audit_codes == awaited
            self.append_message('[+] audit_codes: %s' % audit_codes)
        except AssertionError:
            err = "Audit codes were not: %s" % awaited
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

    def step_2(self):
        election, _, creating = self.get_context()

        creating.run()
        self.append_message('\nAfter running:\n')

        zeus_private_key = election.get_zeus_private_key()
        try:
            assert zeus_private_key != None
            self.append_message('[+] zeus_private_key: %s...'
                    % ('%x' % zeus_private_key)[:32])
        except AssertionError:
            err = "No zeus private key has been computed"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        zeus_public_key = election.get_zeus_public_key()
        try:
            assert zeus_public_key != None
            self.append_message('[+] zeus_public_key : %s...'
                    % ('%x' % zeus_public_key['value'].value)[:32])
        except AssertionError:
            err = "No zeus public key has been computed"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        trustees = election.get_trustees()
        try:
            assert trustees != {}
            self.append_message('[+] trustees: \n%s\n' % '\n'.join(22 * ' ' +
                '%s...' % ('%x' % trustee['value'].value)[:32]
                    for trustee in trustees))
        except AssertionError:
            err = "No trustees have been created"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        trustee_keys = election.get_trustee_keys()
        try:
            assert trustee_keys == list('%x' % trustee['value'].value for trustee in trustees)
            self.append_message('[+] Keys matched')
        except AssertionError:
            err = "Trustee keys mismatch"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        election_key = election.get_election_key()
        try:
            assert election_key != None
            self.append_message('[+] election_key:     %s...'
                    % ('%x' % election_key)[:32])
        except AssertionError:
            err = "No election key has been computed"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        candidates = election.get_candidates()
        try:
            assert candidates != []
            self.append_message('[+] candidates: \n%s' % '\n'.join(22 * ' ' +
                candidate for candidate in candidates))
        except AssertionError:
            err = "No candidates have been created"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        voters = election.get_voters()
        try:
            assert voters != {}
            self.append_message('[+] voters: \n%s' % '\n'.join(22 * ' ' +
                '%s...' % voter_key[:32] for voter_key in voters))
        except AssertionError:
            err = "No voters have been created"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)

        audit_codes = election.get_audit_codes()
        try:
            assert audit_codes != {}
            self.append_message('[+] audit_codes: \n%s' % '\n'.join(22 * ' ' +
            '%s...: %s' % (voter_key[:16], voter_codes)
                    for voter_key, voter_codes in audit_codes.items()))
        except AssertionError:
            err = "No audit_codes have been created"
            self.append_message('[-] %s\n' % err)
            raise AssertionError(err)


if __name__ == '__main__':
    print('\n================== Testing election stage: Creating ==================')
    time.sleep(.6)
    unittest.main()
