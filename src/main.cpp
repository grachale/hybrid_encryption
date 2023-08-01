#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

#define BUFFER_SIZE 4096


void ctxDeleter(EVP_CIPHER_CTX * ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}
void keyDeleter(EVP_PKEY * pubKey)
{
    EVP_PKEY_free(pubKey);
}

bool seal( const char * inFile, const char * outFile, const char * publicKeyFile, const char * symmetricCipher)
{
    if ( !inFile || !outFile || !publicKeyFile || !symmetricCipher )
    {
        if (outFile)
            remove(outFile);
        return false;
    }

    ifstream inputFile (inFile, ios::in | std::ios::binary );
    if ( !inputFile .  is_open() )
    {
        if (outFile)
            remove(outFile);
        return false;
    }

    ofstream outputFile ( outFile, ios::out | std::ios::binary);
    if ( !outputFile . is_open () )
    {
        remove(outFile);
        return false;
    }

    FILE * filePubKey = fopen(publicKeyFile, "rb");
    if (!filePubKey )
    {
        remove(outFile);
        return false;
    }

    EVP_PKEY * temp = PEM_read_PUBKEY(filePubKey, nullptr, nullptr, nullptr);
    fclose(filePubKey);
    if ( !temp )
    {
        remove(outFile);
        return false;
    }
    shared_ptr<EVP_PKEY> pubKey (temp, keyDeleter);

    OpenSSL_add_all_algorithms();

    const EVP_CIPHER * cipher = EVP_get_cipherbyname(symmetricCipher);
    if (!cipher)
    {
        remove(outFile);
        return false;
    }

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), ctxDeleter);
    if (!ctx . get () )
    {
        remove(outFile);
        return false;
    }

    unsigned char * ek [1];
    unique_ptr<unsigned char []> ek1 = make_unique<unsigned char []>(EVP_PKEY_size(pubKey . get ()));
    if ( !ek1 )
    {
        remove(outFile);
        return false;
    }
    ek[0] = ek1 . get();

    unique_ptr<unsigned char []> iv = make_unique <unsigned char []> (EVP_CIPHER_iv_length(cipher));
    EVP_PKEY* recipients [1];
    recipients[0] = pubKey . get ();

    int encryptedKeyLength = 0;
    if (!EVP_SealInit(ctx.get(), cipher, ek, &encryptedKeyLength, iv . get(), recipients, 1))
    {
        remove(outFile);
        return false;
    }


    // NID to outputFile
    int nid = EVP_CIPHER_nid(cipher);
    outputFile . write(reinterpret_cast<const char*>(&nid), sizeof(nid));
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    // EKlen to outputFile
    outputFile . write (reinterpret_cast<const char*>(&encryptedKeyLength), sizeof(encryptedKeyLength));
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    // ek1 to outputFile
    outputFile . write (reinterpret_cast<const char*>(ek1 . get()), encryptedKeyLength);
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    // IV to outputFile
    outputFile . write (reinterpret_cast<const char*>(iv .get()), EVP_CIPHER_iv_length(cipher));
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    uint8_t buffer          [BUFFER_SIZE];
    uint8_t encryptedBuffer [BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    int readSize;
    int outLength;
    while ( true )
    {
        inputFile . read (reinterpret_cast<char *>(buffer), BUFFER_SIZE );

        if ( inputFile . fail () && inputFile . eof() )
            break;

        if ( inputFile . fail () && !inputFile . eof() )
        {
            remove(outFile);
            return false;
        }

        readSize = inputFile . gcount();

        if ( !EVP_SealUpdate(ctx . get (), encryptedBuffer, &outLength, buffer, readSize) )
        {
            remove(outFile);
            return false;
        }

        outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
        if ( !outputFile . good() )
        {
            remove(outFile);
            return false;
        }
    }
    readSize = inputFile . gcount();

    if ( readSize > 0 ) {
        if (!EVP_SealUpdate(ctx.get(), encryptedBuffer, &outLength, buffer, readSize))
        {
            remove(outFile);
            return false;
        }
        outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
        if ( !outputFile . good() )
        {
            remove(outFile);
            return false;
        }
    }

    if ( !EVP_SealFinal(ctx . get (), encryptedBuffer, &outLength) )
    {
        remove(outFile);
        return false;
    }
    outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    return true;
}


bool open( const char * inFile, const char * outFile, const char * privateKeyFile)
{
    if ( !inFile || !outFile || !privateKeyFile )
    {
        if (outFile)
            remove(outFile);
        return false;
    }

    ifstream inputFile (inFile, ios::in | std::ios::binary );
    if ( !inputFile .  is_open() )
    {
        if (outFile)
            remove(outFile);
        return false;
    }

    ofstream outputFile ( outFile, ios::out | std::ios::binary);
    if ( !outputFile . is_open () )
    {
        remove(outFile);
        return false;
    }

    FILE * filePrivateKey = fopen(privateKeyFile, "rb");

    if (!filePrivateKey )
    {
        remove(outFile);
        return false;
    }

    EVP_PKEY * temp = PEM_read_PrivateKey(filePrivateKey, nullptr, nullptr, nullptr);
    fclose(filePrivateKey);
    if (!temp )
    {
        remove(outFile);
        return false;
    }
    shared_ptr<EVP_PKEY> privateKey (temp, keyDeleter);


    int NID;
    inputFile.read(reinterpret_cast<char*>(&NID), sizeof(NID));
    if ( inputFile . fail () )
    {
        remove(outFile);
        return false;
    }

    OpenSSL_add_all_algorithms();

    const EVP_CIPHER * cipher = EVP_get_cipherbynid(NID);
    if (!cipher)
    {
        remove(outFile);
        return false;
    }

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), ctxDeleter);
    if (!ctx . get () )
    {
        remove(outFile);
        return false;
    }

    int EKLen = 0;
    inputFile.read(reinterpret_cast<char*>(&EKLen), sizeof(EKLen));
    if ( inputFile . fail () || EKLen <= 0 )
    {
        remove(outFile);
        return false;
    }

    unique_ptr<unsigned char []> ek1 = make_unique<unsigned char []>(EKLen);
    if (!ek1 . get())
    {
        remove(outFile);
        return false;
    }
    inputFile.read((char*)ek1 . get(), EKLen);
    if ( inputFile . fail () || inputFile . gcount() != EKLen )
    {
        remove(outFile);
        return false;
    }

    unique_ptr<unsigned char []> iv = make_unique <unsigned char []> (EVP_CIPHER_iv_length(cipher));
    inputFile.read((char*)iv . get (), EVP_CIPHER_iv_length(cipher));
    if ( inputFile . fail () || inputFile . gcount() != EVP_CIPHER_iv_length(cipher) )
    {
        remove(outFile);
        return false;
    }

    if (!EVP_OpenInit(ctx . get(), cipher, ek1 . get(), EKLen, iv . get (), privateKey . get() ))
    {
        remove(outFile);
        return false;
    }


    uint8_t buffer          [BUFFER_SIZE];
    uint8_t decryptedBuffer [BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    int readSize;
    int outLength;
    while ( true )
    {
        inputFile . read (reinterpret_cast<char *>(buffer), BUFFER_SIZE );
        if ( inputFile . fail () && inputFile . eof() )
            break;

        if ( inputFile . fail () && !inputFile . eof()  )
        {
            remove(outFile);
            return false;
        }

        readSize = inputFile . gcount();

        if ( !EVP_OpenUpdate(ctx . get (), decryptedBuffer, &outLength, buffer, readSize) )
        {
            remove(outFile);
            return false;
        }

        outputFile . write(reinterpret_cast<const char *>(decryptedBuffer), outLength);
        if ( !outputFile . good() )
        {
            remove(outFile);
            return false;
        }
    }
    readSize = inputFile . gcount();

    if ( readSize > 0 ) {
        if (!EVP_OpenUpdate(ctx.get(), decryptedBuffer, &outLength, buffer, readSize))
        {
            remove(outFile);
            return false;
        }
        outputFile . write(reinterpret_cast<const char *>(decryptedBuffer), outLength);
        if ( !outputFile . good() )
        {
            remove(outFile);
            return false;
        }
    }

    if ( !EVP_OpenFinal(ctx . get (), decryptedBuffer, &outLength) )
    {
        remove(outFile);
        return false;
    }
    outputFile . write(reinterpret_cast<const char *>(decryptedBuffer), outLength);
    if ( !outputFile . good() )
    {
        remove(outFile);
        return false;
    }

    return true;
}



#ifndef __PROGTEST__

int main ( void )
{
    assert( seal("sample/fileToEncrypt", "sample/sealed.bin", "sample/PublicKey.pem", "aes-128-cbc") );
    assert( open("sample/sealed.bin", "sample/openedFileToEncrypt", "sample/PrivateKey.pem") );
    assert( open("sample/sealed_sample.bin", "sample/opened_sample.txt", "sample/PrivateKey.pem") );

    return 0;
}
#endif /* __PROGTEST__ */

