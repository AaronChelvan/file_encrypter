import sys
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util import Padding
import os
import json

BLOCK_SIZE = 16 # AES block size is 16 bytes (128 bits)

KEY_GEN_ROUNDS = 100 # The number of rounds used when generating the key
KEY_LENGTH = 32 # Length of the AES key will be 32 bytes (256 bits)

SALT_GEN_ROUNDS = 12 # The number of rounds used when generating a salt

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

if FUNCTION == "encrypt":
	# Read the file in binary format
	with open(INPUT_FILE, 'rb') as f:
		file_data = f.read()

	# Generate a salt which will be used for generating the key
	key_salt = bcrypt.gensalt(rounds=SALT_GEN_ROUNDS)
	
	# Generate the key for encryption
	key = bcrypt.kdf(password=PASSWORD, salt=key_salt, desired_key_bytes=KEY_LENGTH, rounds=KEY_GEN_ROUNDS)
	
	# Apply padding to the data we want to encrypt
	file_data = Padding.pad(data_to_pad=file_data, block_size=BLOCK_SIZE)

	# Encrypt the padded data
	iv = os.urandom(BLOCK_SIZE)
	encrypter = AES.new(key, AES.MODE_CBC, IV=iv)
	ciphertext = encrypter.encrypt(file_data)

	# Generate a hash of the password
	hashed_password = bcrypt.hashpw(PASSWORD, bcrypt.gensalt(rounds=SALT_GEN_ROUNDS))

	# Overwrite the file with: hashed passkey + IV + key salt + encrypted data
	data = {}
	data["hashed_password"] = hashed_password.decode("ISO-8859-1")
	data["iv"] = iv.decode("ISO-8859-1")
	data["key_salt"] = key_salt.decode("ISO-8859-1")
	data["ciphertext"] = ciphertext.decode("ISO-8859-1")

	with open(INPUT_FILE, 'w') as f:
		f.write(json.dumps(data))
	
	print(INPUT_FILE + " has been encrypted")

elif FUNCTION == "decrypt":
	# Read the file in binary format
	with open(INPUT_FILE, 'r') as f:
		file_data = json.loads(f.read())

	# The encrypted file consists of: hashed passkey, IV, key salt, ciphertext
	hashed_password = file_data["hashed_password"].encode("ISO-8859-1")
	iv = file_data["iv"].encode("ISO-8859-1")
	key_salt = file_data["key_salt"].encode("ISO-8859-1")
	ciphertext = file_data["ciphertext"].encode("ISO-8859-1")

	# Verify that the password is correct
	if not bcrypt.checkpw(PASSWORD, hashed_password):
		print("Password is incorrect!")
		sys.exit(1)

	# Generate the key for decryption
	key = bcrypt.kdf(password=PASSWORD, salt=key_salt, desired_key_bytes=KEY_LENGTH, rounds=KEY_GEN_ROUNDS)
	
	# Decrypt the padded data
	decrypter = AES.new(key, AES.MODE_CBC, IV=iv)
	plaintext = decrypter.decrypt(ciphertext)

	# Remove the padding to obtain the original data
	plaintext = Padding.unpad(padded_data=plaintext, block_size=BLOCK_SIZE)

	# Write the original data back to the file
	with open(INPUT_FILE, 'wb') as f:
		f.write(plaintext)

	print(INPUT_FILE + " has been decrypted")
