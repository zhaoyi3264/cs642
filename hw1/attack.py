# /usr/bin/env python3

# CS 642 University of Wisconsin
#
# usage: python3 attack.py ciphertext
# Outputs a modified ciphertext and tag

import sys
import hashlib

# Grab ciphertext from first argument
ciphertextWithTag = bytes.fromhex(sys.argv[1])

if len(ciphertextWithTag) < 16+16+32:
    print("Ciphertext is too short!")
    sys.exit(0)

iv = ciphertextWithTag[:16]
ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-32]
tag = ciphertextWithTag[len(ciphertextWithTag)-32:]

# Modify the input so the transfer amount is more lucrative to the recipient
message = \
"""AMOUNT: $  37.98
Originating Acct Holder: Alexa
Orgininating Acct #98166-20633

I authorized the above amount to be transferred to the account #51779-31226 
held by a Wisc student at the National Bank of the Cayman Islands.
"""

m0 = 'AMOUNT: $  37.98'
m0_new = 'AMOUNT: $9999999'
int_val = lambda s: int(s.encode('utf-8').hex(), 16)
iv_new = int_val(m0) ^ int_val(m0_new) ^ int.from_bytes(iv, 'big')

message = message.replace(m0, m0_new)
tag = hashlib.sha256(message.encode()).hexdigest()

# Print the new encrypted message
# you can change the print content if necessary
print(hex(iv_new)[2:] + ciphertext[16:].hex() + tag)
