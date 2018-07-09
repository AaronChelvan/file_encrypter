import sys
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util import Padding
import binascii
import os

BLOCK_SIZE = 16 # For AES

KEY_GEN_ROUNDS = 100 # The number of rounds used when generating the key
KEY_LENGTH = 32 # Length of the key used for AES

SALT_GEN_ROUNDS = 12 # The number of rounds used when generating a salt
HASH_LENGTH = 60 # Length of a hash generated by bcrypt

# Check that there is a correct number of arguments
if len(sys.argv) != 4:
	print("Usage: python3 encrypt.py encrypt/decrypt INPUT_FILE PASSWORD")
	sys.exit(1)

# Program arguments
FUNCTION = sys.argv[1]
INPUT_FILE = sys.argv[2]
PASSWORD = sys.argv[3].encode("utf-8")

if FUNCTION not in ["encrypt", "decrypt"]:
	print("Usage: python3 encrypt.py encrypt/decrypt INPUT_FILE PASSWORD")
	sys.exit(1)
	
# Since the bcrypt.kdf() function requires a salt, just use the provided passkey as the salt
# We need to always generate the same key for the same password
key = bcrypt.kdf(password=PASSWORD, salt=PASSWORD, desired_key_bytes=KEY_LENGTH, rounds=KEY_GEN_ROUNDS)

# Read the file in binary format
with open(INPUT_FILE, 'rb') as f:
	file_data = f.read()

if FUNCTION == "encrypt":
	# Apply padding
	file_data = Padding.pad(data_to_pad=file_data, block_size=BLOCK_SIZE)

	# Encrypt the padded data
	IV = os.urandom(BLOCK_SIZE)
	encrypter = AES.new(key, AES.MODE_CBC, IV=IV)
	ciphertext = encrypter.encrypt(file_data)

	# Generate a hash of the password
	hashed_password = bcrypt.hashpw(PASSWORD, bcrypt.gensalt(rounds=SALT_GEN_ROUNDS))

	# Overwrite the file with: hashed passkey + IV + encrypted data
	with open(INPUT_FILE, 'wb') as f:
		f.write(hashed_password + IV + ciphertext)

elif FUNCTION == "decrypt":
	# The encrypted file consists of: hashed passkey + IV + encrypted data
	hashed_password = file_data[0:HASH_LENGTH]
	IV = file_data[HASH_LENGTH:HASH_LENGTH + BLOCK_SIZE]
	ciphertext = file_data[HASH_LENGTH + BLOCK_SIZE:]

	# Verify that the password is correct
	if not bcrypt.checkpw(PASSWORD, hashed_password):
		print("Password is incorrect!")
		sys.exit(1)

	# Decrypt the padded data
	decrypter = AES.new(key, AES.MODE_CBC, IV=IV)
	plaintext = decrypter.decrypt(ciphertext)

	# Remove the padding to obtain the original data
	plaintext = Padding.unpad(padded_data=plaintext, block_size=BLOCK_SIZE)

	# Write the original data back to the file
	with open(INPUT_FILE, 'wb') as f:
		f.write(plaintext)
