#!/usr/bin/env python


import hashlib
import requests

import sys

from uuid import uuid4

from timeit import default_timer as timer

import random


def proof_of_work(last_proof, max_tries=10000000):
	"""
	Multi-Ouroboros of Work Algorithm
	- Find a number p' such that the last five digits of hash(p) are equal
	to the first five digits of hash(p')
	- IE:  last_hash: ...AE912345, new hash 12345888...
	- p is the previous proof, and p' is the new proof
	- Use the same method to generate SHA-256 hashes as the examples in class
	"""

	start = timer()
	random.seed()

	print("Searching for next proof")
	last_five = get_last_five(last_proof)
	proof = random.randint(-9223372036854775806, 9223372036854775807)
	for i in range(max_tries):
		proofstr = str(proof + i)
		if valid_proof(last_five, proofstr):
			print("Proof found: " + proofstr + " in " + str(timer() - start))
			return proofstr

	print("No proof found in " + str(timer() - start))
	return None


def get_last_five(last_proof):
	encoded = str(last_proof).encode()
	last_hash = hashlib.sha256(encoded).hexdigest()
	return last_hash[-5:]


def valid_proof(last_five, proof):
	"""
	Validates the Proof:  Multi-ouroborus:  Do the last five characters of
	the hash of the last proof match the first five characters of the hash
	of the new proof?

	IE:  last_hash: ...AE912345, new hash 12345E88...
	"""
	guess = proof.encode()
	guess_hash = hashlib.sha256(guess).hexdigest()
	# print(last_five, guess_hash[:5])
	return guess_hash[:5] == last_five


if __name__ == '__main__':
	# What node are we interacting with?
	if len(sys.argv) > 1:
		node = sys.argv[1]
	else:
		node = "https://lambda-coin.herokuapp.com/api"

	coins_mined = 0

	# Load or create ID
	f = open("my_id.txt", "r")
	id = f.read()
	print("ID is", id)
	f.close()

	if id == 'NONAME\n':
		print("ERROR: You must change your name in `my_id.txt`!")
		exit()
	# Run forever until interrupted
	old_proof = None
	while True:
		# Get the last proof from the server
		new_proof = None
		while new_proof is None:
			if old_proof is None:
				print()
				print('Getting last_proof...')
				start = timer()
				data = {}
				while 'proof' not in data:
					try:
						r = requests.get(url=node + "/last_proof")
						data = r.json()
						print(f'Got last_proof after {str(timer() - start)}: {data}')
					except Exception as e:
						print(f'Exception: {e}')
				new_proof = proof_of_work(data['proof'])
			else:
				new_proof = proof_of_work(old_proof)

		post_data = {
			"proof": new_proof,
			"id": id
		}

		try:
			r = requests.post(url=node + "/mine", json=post_data)
			data = r.json()
			if data.get('message') == 'New Block Forged':
				coins_mined += 1
				print("Total coins mined: " + str(coins_mined))
				while True:
					old_proof = new_proof
					new_proof = proof_of_work(old_proof)
					post_data = {
						"proof": new_proof,
						"id": id
					}
					for i in range(2):
						print("Posting new coin")
						try:
							requests.post(url=node + "/mine", json=post_data, timeout=2.0)
						except Exception as e:
							pass
					coins_mined += 1
					print("Total coins mined: " + str(coins_mined))
			else:
				print(data.get('message'))
				print(data)
				old_proof = None
		except Exception as e:
			print(f'Exception: {e}')
