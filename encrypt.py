import sys
import bcrypt
from Crypto.Cipher import AES
import binascii
import os

if len(sys.argv) != 5:
	print("Usage: python3 encrypt.py encrypt/decrypt INPUT_FILE OUTPUT_FILE PASSKEY")
	sys.exit(1)

FUNCTION = sys.argv[1]
INPUT_FILE = sys.argv[2]
OUTPUT_FILE = sys.argv[3]
PASSKEY = sys.argv[4].encode("utf-8")

# Read the file in binary format
with open(INPUT_FILE, 'rb') as f:
	file_data = f.read()

# Since the bcrypt.kdf() function requires a salt, just use the provided passkey as the salt
key = bcrypt.kdf(password=PASSKEY, salt=PASSKEY, desired_key_bytes=32, rounds=100)

print(file_data)

IV = os.urandom(16)
encrypter = AES.new(key, AES.MODE_CBC, IV=IV)

#TODO - Padding
while len(file_data)%16 != 0:
	file_data += b"0"

ciphertext = encrypter.encrypt(file_data)
print(ciphertext)

decrypter = AES.new(key, AES.MODE_CBC, IV=IV)
plaintext = decrypter.decrypt(ciphertext)
print(plaintext)