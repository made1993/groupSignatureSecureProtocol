#include "../include/funcionesAES.h"

int main (int argc, char ** argv){
	int ciphlen = 0;
	unsigned char usr_key[] = "FkQCx$K9A:KWQo'P^/.6*qGRyXkRS";
	unsigned char msg[] = "HOLA MUNDO";
	unsigned char* ivec =  NULL;
	unsigned char* cipher = NULL;
	unsigned char* plain = NULL;
	EVP_CIPHER_CTX* ctx = NULL;

	ctx = create_ctx();
	ivec = malloc(11);
	strcpy((char*)ivec, "0123456789");


	ciphlen = encrypt_cbc256(ctx, usr_key, ivec, msg, &cipher, strlen((const char*)msg)+1);
	decrypt_cbc256(ctx, usr_key, ivec, cipher, &plain, ciphlen);
	printf("%s\n", plain);
	
	ivec = realloc(ivec, ciphlen);
	memcpy(ivec, cipher, ciphlen);

	free(cipher);
	free(plain);
	
	ciphlen = encrypt_cbc256(ctx, usr_key, ivec, msg, &cipher, strlen((const char*)msg)+1);
	decrypt_cbc256(ctx, usr_key, ivec, cipher, &plain, ciphlen);
	printf("%s\n", plain);
	free(cipher);
	free(plain);
	

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}