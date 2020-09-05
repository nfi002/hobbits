#include "cipher.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <QProcess>
#include <iomanip>
#include <string>
#include <string.h>
#include <iostream>
#include <openssl/x509.h>

Cipher::Cipher(QObject *parent) : QObject(parent)
{
    initialize();
}

Cipher::~Cipher()
{
    finalize();
}

RSA *Cipher::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsaPubKey;
}

RSA *Cipher::getPublicKey(QString filename)
{
    QByteArray data = readFile(filename);
    return getPublicKey(data);
}

RSA *Cipher::getPrivateKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsaPrivKey;
}

RSA *Cipher::getPrivateKey(QString filename)
{
    QByteArray data = readFile(filename);
    return getPrivateKey(data);
}

QByteArray Cipher::encryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char* str = (const unsigned char*)data.constData();
    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);

    int resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, key, PADDING);
    if(resultLen == -1){
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);
    return buffer;
}

QByteArray Cipher::decryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char* encryptedData = (const unsigned char*)data.constData();

    //int dataSize = data.length();
    //const unsigned char* str = (const unsigned char*)data.constData();
    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);

    int resultLen = RSA_private_decrypt(rsaLen, encryptedData, ed, key, PADDING);
    if(resultLen == -1){
        qCritical() << "Could not decrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    //buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);
    buffer = QByteArray::fromRawData((const char*)ed, resultLen);
    return buffer;
}

void Cipher::freeRSAKey(RSA *key){

    RSA_free(key);
}

void Cipher::initialize()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void Cipher::finalize()
{
   EVP_cleanup();
   ERR_free_strings();
}

QByteArray Cipher::readFile(QString filename)
{
    QByteArray data;
    QFile file(filename);
    if(!file.open(QFile::ReadOnly)){
        qCritical() << file.errorString();
        return data;
    }
    data = file.readAll();
    file.close();
    return data;
}

