import pytest

from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_GENERATOR,
                              _2048_ORDER, _2048_KEY, _2048_PUBLIC,
                              _4096_PRIME, _4096_ELEMENT, _4096_GENERATOR,
                              _4096_ORDER, _4096_KEY, _4096_PUBLIC)
from crypto.exceptions import (WrongCryptoError)
from crypto.modprime import ModPrimeCrypto

# # Cryptosystem construction
#
# _wrong_config__type = [
#     (
#         {'anything...'},
#         'anything unsupported'
#     ),
#     (
#         {'modulus': 5, 'root_order': 2, 'element':3, 'extra':0}, # extra field
#         'integer'
#     ),
#     (
#         {'modulus': 5, 'root_order': 2},                         # missing field
#         'integer'
#     ),
#     (
#         {'modulus': 5, 'wrong_field': 2, 'element':3},           # wrong field
#         'integer'
#     ),
# ]
#
# @pytest.mark.parametrize('config, _type', _wrong_config__type)
# def test_WrongConfigsError(config, _type):
#     with pytest.raises(WrongConfigsError):
#         make_cryptosys(config, _type)
#
# _configs_and_parameters = [
#     (
#         _2048_PRIME,
#         2,
#         _2048_ELEMENT,
#         _2048_GENERATOR,
#         _2048_ORDER
#     ),
#     (
#         _4096_PRIME,
#         2,
#         _4096_ELEMENT,
#         _4096_GENERATOR,
#         _4096_ORDER
#     )
# ]
#
# @pytest.mark.parametrize('modulus, root_order, element, generator, order', _configs_and_parameters)
# def test_make_cryptosys(modulus, root_order, element, generator, order):
#
#     cryptosys = make_cryptosys(config={
#         'modulus': modulus,
#         'root_order': root_order,
#         'element': element
#     }, _type='integer')
#
#     assert cryptosys == {
#         'parameters': {
#             'modulus': modulus,
#             'generator': generator,
#             'order': order
#         },
#         'type': 'integer'
#     }
#
#
# _cryptosys_secret_public_extras__bool = [
#     (
#         {
#             'parameters': {
#                 'modulus': _2048_PRIME,
#                 'generator': _2048_GENERATOR,
#                 'order': _2048_ORDER
#             },
#             'type': 'integer'
#         },
#         _2048_KEY,
#         _2048_PUBLIC,
#         [0, 7, 11, 666],
#         [0, 7, 11, 666],
#         True
#     ),
#     (
#         {
#             'parameters': {
#                 'modulus': _2048_PRIME,
#                 'generator': _2048_GENERATOR,
#                 'order': _2048_ORDER,
#             },
#             'type': 'integer'
#         },
#         12345,                                                 # Wrong logarithm
#         _2048_PUBLIC,
#         [0, 7, 11, 666],
#         [0, 7, 11, 666],
#         False
#     ),
#     (
#         {
#             'parameters': {
#                 'modulus': _2048_PRIME,
#                 'generator': _2048_GENERATOR,
#                 'order': _2048_ORDER,
#             },
#             'type': 'integer'
#         },
#         _2048_KEY,
#         _2048_PUBLIC,
#         [0, 7, 11, 666],
#         [1, 7, 11, 666],                                          # Wrong extras
#         False
#     ),
#     (
#         {
#             'parameters': {
#                 'modulus': _4096_PRIME,
#                 'generator': _4096_GENERATOR,
#                 'order': _4096_ORDER
#             },
#             'type': 'integer'
#         },
#         _4096_KEY,
#         _4096_PUBLIC,
#         [0, 7, 11, 666],
#         [0, 7, 11, 666],
#         True
#     ),
# ]
#
# @pytest.mark.parametrize(
#     'cryptosys, secret, public, extras_1, extras_2, _bool',
#     _cryptosys_secret_public_extras__bool
# )
# def test_schnorr_protocol(cryptosys, secret, public, extras_1, extras_2, _bool):
#
#     schnorr_proof = make_schnorr_proof(cryptosys)
#     schnorr_verify = make_schnorr_verify(cryptosys)
#
#     import json
#     print(json.dumps(cryptosys, indent=4, sort_keys=True))
#
#     proof = schnorr_proof(secret, public, *extras_1)
#     valid = schnorr_verify(proof, public, *extras_2)
#     print(valid)
#
#     assert valid is _bool
