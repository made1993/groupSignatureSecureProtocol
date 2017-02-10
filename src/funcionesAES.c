#include "../include/funcionesAES.h"

EVP_CIPHER_CTX* create_ctx(){
	EVP_CIPHER_CTX* ctx = NULL;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	
	return ctx;
}

int encrypt_cbc256(EVP_CIPHER_CTX* ctx, unsigned char* key, unsigned char* iv,
			const unsigned char* text, unsigned char** out, int textlen){	
	
	int tmp = 0, ciphlen = 0;
	
	if(ctx == NULL || key == NULL || iv == NULL ||
		text == NULL || out == NULL || textlen<1)
		return 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	*out = calloc(textlen+64, sizeof(char));
	
	EVP_EncryptUpdate(ctx, *out, &tmp, text, textlen);
	ciphlen = tmp;

	EVP_EncryptFinal_ex(ctx, (*out) + tmp, &tmp);
	ciphlen += tmp;
	EVP_CIPHER_CTX_cleanup(ctx);
	*out = realloc(*out, ciphlen);
	return ciphlen;
}

int decrypt_cbc256(EVP_CIPHER_CTX* ctx, unsigned char* key, unsigned char* iv,
		const unsigned char* text, unsigned char** out, int textlen){
	
	int tmp = 0 , deciphlen = 0;
	
	if(ctx == NULL || key == NULL || iv == NULL ||
		text == NULL || out == NULL || textlen<1)
		return 0;

	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	*out = calloc(textlen, sizeof(char));

	EVP_DecryptUpdate(ctx, *out, &tmp, text, textlen);
	deciphlen = tmp;

	EVP_DecryptFinal_ex(ctx, (*out) +tmp, &tmp);
	deciphlen += tmp;

	*out = realloc(*out, deciphlen);
	EVP_CIPHER_CTX_cleanup(ctx);

	return deciphlen;

}