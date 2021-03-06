"""
"""

ALPHA = 0
BETA  = 1
PROOF = 2

VOTER_KEY_CEIL  = 2 ** 256
VOTER_SLOT_CEIL = 2 ** 48
MIN_MIX_ROUNDS  = 3

MIN_VOTE_JSON_KEYS   = ['voter', 'encrypted_ballot', 'fingerprint']
MAX_VOTE_JSON_KEYS   = ['voter', 'encrypted_ballot', 'fingerprint',
        'audit_code', 'voter_secret']
ENC_BALLOT_JSON_KEYS = ['public', 'alpha', 'beta',
        'commitment', 'challenge', 'response']

NONE = 'NONE'

V_CAST_VOTE     =   'CAST VOTE'
V_PUBLIC_AUDIT  =   'PUBLIC AUDIT'
V_PUBLIC_AUDIT_FAILED = 'PUBLIC AUDIT FAILED'
V_AUDIT_REQUEST =   'AUDIT REQUEST'

V_FINGERPRINT   =   'FINGERPRINT: '
V_INDEX         =   'INDEX: '
V_PREVIOUS      =   'PREVIOUS VOTE: '
V_VOTER         =   'VOTER: '
V_ELECTION      =   'ELECTION PUBLIC: '
V_ZEUS_PUBLIC   =   'ZEUS PUBLIC: '
V_TRUSTEES      =   'TRUSTEE PUBLICS: '
V_CANDIDATES    =   'CANDIDATES: '
V_MODULUS       =   'MODULUS: '
V_GENERATOR     =   'GENERATOR: '
V_ORDER         =   'ORDER: '
V_ALPHA         =   'ALPHA: '
V_BETA          =   'BETA: '
V_COMMITMENT    =   'COMMITMENT: '
V_CHALLENGE     =   'CHALLENGE: '
V_RESPONSE      =   'RESPONSE: '
V_COMMENTS      =   'COMMENTS: '

V_SEPARATOR = '\n-----------------\n'
