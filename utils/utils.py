from .random import random_integer

# Returns the integer represented in LSB by the provided string's UTF-8 encoding
int_from_bytes = lambda _bytes: int.from_bytes(_bytes, byteorder='little')

def extract_value(dictionary, key, cast, default=None):
	"""
	:type dictionary: dict
	:type key: str
	:type cast: function
	:type default:
	"""
	value = default
	if key in dictionary.keys():
	    if dictionary[key] is None:
	        return None
	    value = cast(dictionary[key])
	return value

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
