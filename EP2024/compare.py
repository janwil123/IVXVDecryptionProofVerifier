# This script compares the ciphertext sets of the mixer output 
# and the decryption proof file

import json

with open('config.json') as f:
    files = json.load(f)

with open(files['prooffile']) as f:
    proofs = json.load(f)

with open(files['mixedfile']) as f:
    mixer_out = json.load(f)

proof_ciphertexts = []

for proof in proofs['proofs']:
    proof_ciphertexts.append(proof['ciphertext'])

mixed_ciphertexts = []

districts = mixer_out['districts']['0000.1']

for district in districts:
    mixed_ciphertexts +=  districts[district]['EP_2024.question-1']

if sorted(proof_ciphertexts)==sorted(mixed_ciphertexts):
    print("The ciphertext sets match.")
else:
    print("The ciphertext sets do not match.")
    