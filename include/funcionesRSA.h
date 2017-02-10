#ifndef FUNCIONESRSA_H
#define FUNCIONESRSA_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "conexion.h"


#define SHA256_SIGLEN 256


/**
*	
*		
*	
*	
*	
*	
*	
*	
**/
int generateKeysRSA(EVP_PKEY** privKey, EVP_PKEY** pubKey);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int signMsgRSA(EVP_PKEY* key, const unsigned char* msg, unsigned char** sig, size_t* slen, size_t msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int verifySignRSA(EVP_PKEY* key, const unsigned char* sig, const unsigned char* msg, size_t slen, size_t msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int reciveRSAsign(int sockfd, EVP_PKEY* pubKey, unsigned char** msg);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int sendRSAsign(int sockfd, EVP_PKEY* privKey, const unsigned char* msg, int msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int msgToRSApubKey(EVP_PKEY** pubKey, char* msg, int msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int RSApubKeyToMsg(EVP_PKEY* pubKey, char** msg, int* msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int RSAfileToPubKey(EVP_PKEY** pubKey, char* fname);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int RSApubKeyToFile(EVP_PKEY* pubKey, char* fname, int* msglen);


/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int RSAfileToPrivKey(EVP_PKEY** privKey, char* fname);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int RSAprivKeyToFile(EVP_PKEY* privKey, char* fname, int* msglen);

/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int reciveRSAkey(int sockfd, EVP_PKEY** pubKey);
/**
*	
*	
*	
*	
*	
*	
*	
*	
**/
int sendRSAkey(int sockfd, EVP_PKEY* pubKey);

#endif