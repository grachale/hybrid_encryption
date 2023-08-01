# Hybrid encryption
Implementation of two functions in C++ (seal and open) that encrypt/decrypt data using hybrid encryption.

## Function Parameters for "seal":

bool seal(const char* inFile, const char* outFile, const char* publicKeyFile, const char* symmetricCipher);

inFile: The file containing binary data to be encrypted.

outFile: The output file where all necessary information for decryption will be stored.

publicKeyFile: The public key to be used for encrypting the symmetric key.

symmetricCipher: The name of the symmetric cipher used for encryption.

Return value: true on success, false otherwise. If the function fails, you must ensure that the output file outFile will not exist.

The seal function generates a symmetric key and an initialization vector (IV) as inputs for the symmetric cipher symmetricCipher. Using this cipher, key, and IV, the function encrypts the data in inFile. The key for the symmetric cipher is encrypted with an asymmetric cipher (RSA) using the public key stored in publicKeyFile.

## Function Parameters for "open":

bool open(const char* inFile, const char* outFile, const char* privateKeyFile);

inFile: The encrypted file in the same format as the output file from the seal function.

outFile: The output file where all decrypted data will be stored (expecting binary match with the input file from the seal function).

privateKeyFile: The private key used for decrypting the encrypted key.

Return value: true on success, false otherwise. If the function fails, you must ensure that the output file outFile will not exist.
