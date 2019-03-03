# file_encrypter

## Usage
### Encryption 
`python3 encrypt.py encrypt FILE_NAME PASSWORD`

The encrypted file is a JSON file consisting of: the hashed password, the IV, the salt used for generating the key, and the encrypted data.

### Decryption
`python3 encrypt.py decrypt FILE_NAME PASSWORD`

Providing the wrong password during decryption will raise an error.

## Dependencies
See requirements.txt
