import sys
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util import Padding
import binascii
import os

BLOCK_SIZE = 16

if len(sys.argv) != 5:
	print("Usage: python3 encrypt.py encrypt/decrypt INPUT_FILE OUTPUT_FILE PASSKEY")
	sys.exit(1)

FUNCTION = sys.argv[1]
INPUT_FILE = sys.argv[2]
OUTPUT_FILE = sys.argv[3]
PASSKEY = sys.argv[4].encode("utf-8")


# Since the bcrypt.kdf() function requires a salt, just use the provided passkey as the salt
key = bcrypt.kdf(password=PASSKEY, salt=PASSKEY, desired_key_bytes=32, rounds=100)

# Read the file in binary format
with open(INPUT_FILE, 'rb') as f:
	file_data = f.read()
#print(file_data)

#if FUNCTION == "encrypt":
# Apply padding
file_data = Padding.pad(data_to_pad=file_data, block_size=BLOCK_SIZE)

# Encrypt the padded data
IV = os.urandom(BLOCK_SIZE)
print("IV len = " + str(len(IV)))
print(IV)
encrypter = AES.new(key, AES.MODE_CBC, IV=IV)
ciphertext = encrypter.encrypt(file_data)
print(ciphertext)

# Overwrite the file with: hashed passkey + IV + encrypted data
hashed_passkey = bcrypt.hashpw(PASSKEY, bcrypt.gensalt(rounds=12))
print(hashed_passkey)
print(len(hashed_passkey))	

with open(OUTPUT_FILE, 'w') as f:
	f.write(str(hashed_passkey) + "|||" + str(IV) + "|||" + str(ciphertext))

#elif FUNCTION == "decrypt":
with open(OUTPUT_FILE, 'r') as f:
	file_data = f.read()

# The encrypted file consists of: hashed passkey + IV + encrypted data
#hashed_passkey = file_data[0:60]
#IV = file_data[60:60 + BLOCK_SIZE]
#ciphertext = file_data[60 + BLOCK_SIZE:]
hashed_passkey = file_data.split("|||")[0]
IV2 = file_data.split("|||")[1]
ciphertext = file_data.split("|||")[2]

print("hashed_passkey = ")
print(hashed_passkey)
print("\nIV = ")
print(IV2)
print("\nciphertext = ")
print(ciphertext)
print(ciphertext.encode("latin-1"))

# Verify that the passkey is correct

# Extract the IV

# Decrypt the padded data
decrypter = AES.new(key, AES.MODE_CBC, IV=IV)
plaintext = decrypter.decrypt(ciphertext.encode("utf-8"))

# Remove the padding to obtain the original text
plaintext = Padding.unpad(padded_data=plaintext, block_size=BLOCK_SIZE)
print(plaintext)
