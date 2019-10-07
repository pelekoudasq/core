import pytest

from zeus_core.utils.gamma_encoding import (_get_choice_params, gamma_encode,
    gamma_encoding_max, encode_selection)


# _get_choice_params

__nr_choices__nr_candidates__max_choices__result = [
    (1, None, None, (1, 1)),
    (1, 2, None, (2, 2)),
    (1, 2, 3, (2, 3))
]

@pytest.mark.parametrize('nr_choices, nr_candidates, max_choices, result',
    __nr_choices__nr_candidates__max_choices__result)
def test__get_choice_params(nr_choices, nr_candidates, max_choices, result):
    nr_candidates, max_choices = \
        _get_choice_params(nr_choices, nr_candidates, max_choices)
    assert result == (nr_candidates, max_choices)

__AssertionError_in__get_choice_params = [
    (-1, 1, 1), (0, 0, 1), (0, 1, 0), (2, 1, 1)]

@pytest.mark.parametrize('nr_choices, nr_candidates, max_choices',
    __AssertionError_in__get_choice_params)
def test_AssertionError_in__get_choice_params(nr_choices, nr_candidates, max_choices):
    with pytest.raises(AssertionError):
        _get_choice_params(nr_choices, nr_candidates, max_choices)


# gamma_encode

__choices__nr_candidates__max_choices__result = [
    ([22347], None, None, 22348),
    ([22347, 7823], 2, None, 30173),
    ([22347, 7823, 3245], 2, 3, 3250)
]

@pytest.mark.parametrize('choices, nr_candidates, max_choices, result',
    __choices__nr_candidates__max_choices__result)
def test__gamma_encode(choices, nr_candidates, max_choices, result):
    encoding = gamma_encode(choices, nr_candidates, max_choices)
    assert result == encoding

__AssertionError_in_gamma_encode = [
    ([], 0, 1), ([], 1, 0), ([1, 2], 1, 1)]

@pytest.mark.parametrize('choices, nr_candidates, max_choices',
    __AssertionError_in_gamma_encode)
def test_AssertionError_in_gamma_encode(choices, nr_candidates, max_choices):
    with pytest.raises(AssertionError):
        gamma_encode(choices, nr_candidates, max_choices)


# gamma_encoding_max

__nr_candidates__max_choices__result = [
    (0, 0, 0), (0, 1, 0),
    (1, 1, 1), (1, 2, 1),
    (77, 11, 270751738727809768429)
]

@pytest.mark.parametrize('nr_candidates, max_choices, result',
    __nr_candidates__max_choices__result)
def test__gamma_encoding_max(nr_candidates, max_choices, result):
    encoding = gamma_encoding_max(nr_candidates, max_choices)
    assert result == encoding

__AssertionError_in_gamma_encoding_max = [
    (1, 0), (100, 0), (11, 77)]

@pytest.mark.parametrize('nr_candidates, max_choices',
    __AssertionError_in_gamma_encoding_max)
def test_AssertionError_in_gamma_encoding_max(nr_candidates, max_choices):
    with pytest.raises(AssertionError):
        gamma_encoding_max(nr_candidates, max_choices)


# encode_selection

__AssertionError_in_encode_selection = [
    ([0, 1], 0), ([0, 1], 1)]

@pytest.mark.parametrize('selection, nr_candidates',
    __AssertionError_in_encode_selection)
def test_encode_selection(selection, nr_candidates):
    with pytest.raises(AssertionError):
        encode_selection(selection, nr_candidates)


__selection__nr_candidates__result = [
    ([0], None, 1), ([0], 10, 1),
    ([0, 1], None, 4), ([0, 1], 10, 12),
    ([0, 1, 2], None, 13), ([0, 1, 2], 10, 111),
    ([0, 1, 2, 3], None, 48), ([0, 1, 2, 3], 10, 894)
]

@pytest.mark.parametrize('selection, nr_candidates, result',
    __selection__nr_candidates__result)
def test_encode_selection(selection, nr_candidates, result):
    encoding = encode_selection(selection, nr_candidates)
    assert result == encoding
