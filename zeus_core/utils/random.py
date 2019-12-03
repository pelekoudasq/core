from secrets import token_bytes
from .utils import int_from_bytes


def random_integer(min, max):
    """
    Inclusive resp. exclusive lower resp. upper bound
    """
    range = max - min
    nr_bits = max.bit_length()
    nr_bytes = int((nr_bits - 1) / 8) + 1
    random_bytes = token_bytes(nr_bytes)
    num = int_from_bytes(random_bytes)
    shift = num.bit_length() - nr_bits
    if shift > 0:
        num >>= shift
    if num >= max:
        num -= max
    return num + min


def random_permutation(nr_elements):
    """
    :type nr_elements: int
    :type: list[int]
    """
    return _selection_to_permutation(random_selection(nr_elements, full=True))


def random_selection(nr_elements, full=True):
    """
    Generates and returns a random list of non-negative integers

    If `full` is left to the default value `True`, the list will have exactly
    `nr_elements`, otherwise the list's length will be random and inclusively
    bounded by `nr_elements`; in either case, each number will be exclusively
    bounded by `nr_elements` minus its (zero-based) position within the list

    :type nr_elements: int
    :type full: bool
    :rtype: list[int]

    .. note:: if the provided `nr_elements` is <=0 then the list [0] is returned
    """
    selection = []
    variable = not full
    append = selection.append

    for i in range(nr_elements, 1, -1):
        r = random_integer(0, i + variable)
        if r == i:
            break                            # Randomizes the selection's length
        append(r)
    else:
        # ~ Needed for the case full=1: guarantees that the last element
        # ~ is equal to 0 if the above loop did not happen to break
        append(0)
    return selection


def _selection_to_permutation(selection):
	"""
    Returns a permutation of the first n non-negative integers, where n is
    equal to the length of the provided `selection` argument

    The generated permutation is determined by the `selection` argument, which
    should be a list of non-negative integers like the one returned by the
    `random_selection()` function

    :type selection: list[int]
    :rtype: list[int]
    """
	nr_elements = len(selection)

	lefts = [None] * nr_elements
	rights = [None] * nr_elements

	leftpops = [0] * nr_elements
	pop = 1

	iter_selection = iter(reversed(selection))

	next(iter_selection)							  # Ignore the first element
	for pos in iter_selection:
		node = 0
		cur = 0
		depth = 0

		while 1:
			leftpop = leftpops[node]
			newcur = cur + leftpop + 1
			if pos >= newcur:
				right = rights[node]
				if right is None:
					rights[node] = pop
					pop += 1
					break
				node = right
				cur = newcur
			else:
				leftpops[node] += 1
				left = lefts[node]
				if left is None:
					lefts[node] = pop
					pop += 1
					break
				node = left

	maxdepth = 0
	depth = 0
	stack = [0]
	append = stack.append
	pop = stack.pop

	permutation = [None] * nr_elements
	offset = 0

	while stack:
		node = pop()
		if node < 0:
			permutation[nr_elements + node] = offset
			offset += 1
			continue

		depth += 1
		if depth > maxdepth:
			maxdepth = depth

		right = rights[node]
		if right is not None:
			append(right)
		append(- node - 1)
		left = lefts[node]
		if left is not None:
			append(left)

	return permutation


def random_party_selection(nr_elements, nr_parties):
    """
    """
    party = random_integer(0, nr_parties)
    per_party = nr_elements // nr_parties
    low = party * per_party
    high = (party + 1) * per_party
    if nr_elements - high < per_party:
        high = nr_elements
    choices = []
    append = choices.append
    r = random_integer(0, 2 ** (high - low))
    for i in range(low, high):
        skip = r & 1
        r >>= 1
        if skip:
            continue
        append(i)
    return to_relative_answers(choices, nr_elements)


def to_relative_answers(choices, nr_candidates):
	"""
    Answer choices helper, convert absolute indexed answers to relative.

    e.g. for candidates [A, B, C] absolute choices [1, 2, 0] will be converted
    to [1, 1, 0].
    """
	relative = []
	candidates = list(range(nr_candidates))
	choices = [candidates.index(c) for c in choices]
	for choice in choices:
		index = candidates.index(choice)
		relative.append(index)
		candidates.remove(choice)
	return relative
