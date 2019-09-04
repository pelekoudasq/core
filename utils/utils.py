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

#TODO
def to_relative_answers(choices, nr_candidates):
	pass

#TODO
def get_random_party_selection(nr_elements, nr_parties):
	pass
