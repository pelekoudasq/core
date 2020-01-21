from zeus_core.utils import to_canonical, from_canonical

obj = {
    'a': 0, 'b': 'test',
    'c': ['message', 1, 2],
    'd': {'alpha': 666, 'beta': (3, 4, 'six')}
}

enc = '{\n011_a: 01100,\n011_b: 014_test,\n011_c: [\n017_message,\n01101,' + \
      '\n01102]\n,\n011_d: {\n015_alpha: 013029a,\n014_beta: [\n01103,\n0' + \
      '1104,\n013_six]\n}\n}\n'

dec = {
    'a': 0, 'b': 'test',
    'c': ['message', 1, 2],
    'd': {'alpha': 666, 'beta': [3, 4, 'six']}
}

def test_to_canonincal():
    assert enc == to_canonical(obj)

def test_from_canonical():
    assert dec == from_canonical(enc)
