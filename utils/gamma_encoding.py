
_terms = {}

def _get_term(n, k):
    """
    :type n:
    :type k:
    :rtype: int
    """
    if k >= n:
        return 1

    try:
        t = _terms[n]
    except KeyError:
        t = {n: 1}
        _terms[n] = t
    else:
        if k in t:
            return t[k]

    m = k
    while 1:
        m += 1
        if m in t:
            break

    term = t[m]
    while 1:
        term *= m
        m -= 1
        t[m] = term
        if m <= k:
            break

    return term


_offsets = {}

def _get_offsets(n):
    """
    :type n: int
    :rtype: list[int]
    """
    if n in _offsets:
        return _offsets[n]

    offsets = []
    append = offsets.append
    sumus = 0
    i = 0
    while 1:
        sumus += _get_term(n, n - i)
        append(sumus)
        if i == n:
            break
        i += 1

    _offsets[n] = offsets
    return offsets


_factors = {}

def _get_factor(b, n):
    """
    :type b: int
    :type n: int
    :rtype: int
    """
    if n <= 1:
        return 1

    try:
        t = _factors[b]
    except KeyError:
        t = {1: 1}
        _factors[b] = t
    else:
        if n in t:
            return t[n]

    i = n
    while 1:
        i -= 1
        if i in t:
            break

    factor = t[i]
    while 1:
        factor *= b + i
        i += 1
        t[i] = factor
        if i >= n:
            break

    return factor


def _get_choice_params(nr_choices, nr_candidates=None, max_choices=None):
    """
    :type nr_choinces: int
    :type nr_candidates: int
    :type max_choices: int
    :rtype: tuple
    """
    if nr_candidates is None:
        nr_candidates = nr_choices
    if max_choices is None:
        max_choices = nr_candidates

    if nr_choices < 0 or nr_candidates <= 0 or max_choices <= 0:
        e = 'Invalid parameters: %d < 0 or %d <= 0 or %d <= 0' % (nr_choices, nr_candidates, max_choices)
        raise AssertionError(e)

    if nr_choices > max_choices:
        e = 'Invalid number of choices: %d > %d' % (nr_choices, max_choices)
        raise AssertionError(e)

    return nr_candidates, max_choices


def gamma_encode(choices, nr_candidates=None, max_choices=None):
    """
    :type choices: list[int]
    :type nr_candidates: int
    :type max_choices: int
    :rtype: int
    """
    nr_choices = len(choices)

    try:
        nr_candidates, max_choices = \
            _get_choice_params(nr_choices, nr_candidates, max_choices)
    except AssertionError:
        raise

    if nr_choices == 0:
        return 0

    offsets = _get_offsets(nr_candidates)
    try:
        sumus = offsets[nr_choices - 1]
    except IndexError:
        e = 'Invalid number of choices'
        raise AssertionError(e)

    b = nr_candidates - nr_choices
    i = 1
    while 1:
        sumus += choices[-i] * _get_factor(b, i)
        if i >= nr_choices:
            break
        i += 1

    return sumus


def gamma_encoding_max(nr_candidates, max_choices):
    """
    :type nr_candidates: int
    :type max_choices: int
    :rtype: int
    """
    if max_choices is None:
        max_choices = nr_candidates
    if nr_candidates <= 0:
        return 0
    choices = range(nr_candidates - 1, nr_candidates - max_choices - 1, -1)

    try:
        encoding = gamma_encode(choices, nr_candidates, max_choices)
    except AssertionError:
        raise
    return encoding


def encode_selection(selection, nr_candidates=None):
    """
    :type selection: list
    :type nr_candidates: int
    :rtype: int
    """
    if nr_candidates is None:
        nr_candidates = len(selection)

    try:
        encoding = gamma_encode(selection, nr_candidates, nr_candidates)
    except AssertionError:
        raise
    return encoding
