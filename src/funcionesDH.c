
#include "../include/funcionesDH.h"



int getParamsIniDH(EVP_PKEY** params){
	if(params == NULL)
		return 0;

	*params = NULL;	
	if(NULL == (*params = EVP_PKEY_new()))
		return 0;	 

	if(1 != EVP_PKEY_set1_DH(*params,DH_get_2048_256()))
		return 0;
	
	return 1;
}

int genNewParamsIniDH(EVP_PKEY** params, EVP_PKEY_CTX** pctx){
	
	if(pctx == NULL || params == NULL)
		return 0;
	*pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if(!*pctx){
		return 0;
	}

	if(1 != EVP_PKEY_paramgen_init(*pctx)){
		EVP_PKEY_CTX_free(*pctx);
		return 0;
	}

	if(1 != EVP_PKEY_CTX_set_dh_paramgen_prime_len(*pctx, 2048)){
		EVP_PKEY_CTX_free(*pctx);
		return 0;
	}

	if(1 != EVP_PKEY_paramgen(*pctx, params)){
		EVP_PKEY_CTX_free(*pctx);
		return 0;
	}

	return 1;
}

int genKeyFromParamsDH(EVP_PKEY_CTX** kctx, EVP_PKEY** dhkey, EVP_PKEY* params){
	
	if(kctx == NULL || dhkey == NULL || params == NULL)
	
	*dhkey = NULL;
	if(NULL == (*dhkey = EVP_PKEY_new())) 
		return 0;
	
	/* Create context*/
	if(!(*kctx = EVP_PKEY_CTX_new(params, NULL))){
		return 0;
	}

	/* Generate a new key */
	if(1 != EVP_PKEY_keygen_init(*kctx)){
		EVP_PKEY_CTX_free(*kctx);
		return 0;
	}
	
	if(1 != EVP_PKEY_keygen(*kctx, dhkey)){
		EVP_PKEY_CTX_free(*kctx);
		return 0;
	}

	return 1;
}
unsigned  char* deriveSharedSecretDH(EVP_PKEY* privkey, EVP_PKEY* peerkey){
	unsigned char* skey = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	size_t skeylen;
	if(privkey == NULL || peerkey == NULL)
		return 0;

	ctx = EVP_PKEY_CTX_new(privkey, NULL);
	if (!ctx){
		return NULL;
	}
	if(EVP_PKEY_derive_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	
	if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	skey = OPENSSL_malloc(skeylen);

	if (!skey){
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0){
		OPENSSL_free(skey);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	return skey;
}

int DHpubKeyToMsg(EVP_PKEY* pubKey, char ** msg){
	if(pubKey == NULL || msg == NULL)
		return 0;
	*msg =  NULL;
	return i2d_PUBKEY(pubKey, (unsigned char**) msg);
}



int msgToDHpubKey(EVP_PKEY** pubKey, char * msg, int msglen){
	if(pubKey == NULL || msg == NULL || msglen < 1)
		return 0;

	*pubKey = EVP_PKEY_new();
	if(*pubKey == NULL){
		printf("ERR EVP_PKEY_new\n");
		return 0;
	}
	d2i_PUBKEY(pubKey, (const unsigned char**) &msg, msglen);
	return 1;
}