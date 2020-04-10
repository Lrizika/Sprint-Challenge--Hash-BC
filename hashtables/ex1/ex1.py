#  Hint:  You may not need all of these.  Remove the unused functions.
from hashtables import (HashTable,
						hash_table_insert,
						hash_table_remove,
						hash_table_retrieve,
						hash_table_resize)


def get_indices_of_item_weights(weights, length, limit):
	ht = HashTable(16)
	for key, value in enumerate(weights):
		hash_table_insert(ht, value, key)
	for index, weight in enumerate(weights):
		i2 = hash_table_retrieve(ht, limit - weight)
		if i2:
			return (i2, index)

	return None


def print_answer(answer):
	if answer is not None:
		print(str(answer[0] + " " + answer[1]))
	else:
		print("None")
