#!/usr/bin/env python3
# Encrypts a binary file with AES-256-CBC using a randomly generated key
# The key is prepended to the encrypted data
# Usage: python3 bintoaes.py beacon.bin

import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Save the encrypted bytes to a file
encrypted_file = "encrypted.bin"
with open(encrypted_file, "wb") as file:
    file.write(KEY + ciphertext)

print(f'[+] Saved encrypted file as encrypted.bin (Size: {len(KEY + ciphertext)} bytes)')
