# file_encrypter

## Usage
### Encryption 
`python3 encrypt.py encrypt FILE_NAME PASSWORD`

The encrypted file consists of: the hashed password, the IV, and encrypted data. All 3 of those are appended together in that order.

### Decryption
`python3 encrypt.py decrypt FILE_NAME PASSWORD`

Providing the wrong password during decryption will raise an error.

## Dependencies
See requirements.txt
