#ifndef FUNCIONESAES_H
#define FUNCIONESAES_H

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>


#define TEXT_BLOCK 64


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
EVP_CIPHER_CTX* create_ctx();

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
int encrypt_cbc256(EVP_CIPHER_CTX* ctx, unsigned char* key, unsigned char* iv, 
		const unsigned char* text, unsigned char** out, int textlen);

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
int decrypt_cbc256(EVP_CIPHER_CTX* ctx, unsigned char* key, unsigned char* iv,
		const unsigned char* text, unsigned char** out, int textlen);

#endif