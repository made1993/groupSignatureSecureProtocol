#include "../include/sconexion.h"

#ifdef TIMETESTD

#endif
Sconexion_t* initSconexion(int socket, groupsig_key_t *grpkey,
		groupsig_key_t *memkey, int scheme, EVP_PKEY* keyRSA){
	Sconexion_t* scnx;
	if(socket < 0 || grpkey == NULL  || keyRSA == NULL)
		return NULL;
	scnx =  malloc(sizeof(Sconexion_t));
	scnx->socket = socket;
	scnx->grpkey = grpkey;
	scnx->memkey = memkey;
	scnx->scheme = scheme;
	scnx->keyRSA = keyRSA;
	scnx->key = NULL;
	scnx->iv = NULL;
	scnx->ctx = create_ctx();
	scnx->lastsig = NULL;
	scnx->siglen = 0;
	return scnx;
}

int freeSconexion(Sconexion_t* scnx){
	if(scnx == NULL)
		return 1;
	close(scnx->socket);
	if(scnx->ctx != NULL){
		free(scnx->ctx); scnx->ctx = NULL;
	}

	if(scnx->key != NULL){
		free(scnx->key); scnx->key = NULL;
	}

	if(scnx->iv != NULL){
		free(scnx->iv); scnx->iv = NULL;
	}

	if(scnx->memkey != NULL){
		free(scnx->memkey); scnx->memkey = NULL;
	}
	return 1;
}


int sendClientCiphMsg(Sconexion_t* scnx,const unsigned char* text, int textlen){
	int msglen = 0, bufflen = 0, siglen = 0;
	char*  msg = NULL, *buff = NULL, *sigstr;
	//FILE* f = NULL;

	#ifdef TIMETESTD
	clock_t ini, fin, totc, tots;
	FILE * f = NULL;
	f =fopen("tmedioCd.dat","a");
	#endif

	if(scnx == NULL || scnx->socket == -1 || scnx->ctx == NULL || scnx->key == NULL ||
		scnx->iv == NULL || text == NULL || textlen < 1 || scnx->grpkey == NULL || 
		scnx->memkey == NULL)
		return 0;
	//f = fopen("csend.txt", "a");

	#ifdef TIMETESTD
	ini =  clock();
	siglen = signMsgGS(scnx->grpkey, scnx->memkey, scnx->scheme, (char*)text, &sigstr);
	msglen = sigMsgToStrGS((char*)text, textlen, sigstr, siglen, &msg);	
	fin =  clock();
	tots = fin - ini;
	#else
	siglen = signMsgGS(scnx->grpkey, scnx->memkey, scnx->scheme, (char*)text, &sigstr);
	msglen = sigMsgToStrGS((char*)text, textlen, sigstr, siglen, &msg);
	#endif
	
	#ifdef TIMETESTD
	ini =  clock();
	bufflen = encrypt_cbc256(scnx->ctx, scnx->key, scnx->iv, (const unsigned char*)msg,
				(unsigned char**)&buff, msglen);

	fin =  clock();
	totc = fin - ini;
	fprintf(f, "%ld %ld\n", tots, totc);
	fclose(f);
	#else

	bufflen = encrypt_cbc256(scnx->ctx, scnx->key, scnx->iv, (const unsigned char*)msg,
				(unsigned char**)&buff, msglen);
	#endif

	

	//fprintf(f, "bufflen: %d siglen:%d msg:%d :%s\n", bufflen, siglen , textlen, text);
	//fclose(f);
	
	
	if(bufflen <1)
		return 0;
	msglen = escribir(scnx->socket, buff, bufflen);
	scnx->iv = realloc(scnx->iv, bufflen);
	memcpy(scnx->iv, buff, bufflen);

	free(sigstr);
	free(msg);
	free(buff);
	return msglen;
}

int reciveServerCiphMsg(Sconexion_t* scnx, char** msg){
	int msglen = 0, bufflen = 0, siglen = 0;
	char* buff = NULL, *text =  NULL, *sigstr =  NULL;
	
	if(scnx == NULL || scnx->socket == -1 || scnx->ctx == NULL || scnx->key == NULL ||
		scnx->iv == NULL || scnx->grpkey == NULL || msg == NULL){
		fprintf(stdout, "Error: NULL input at reciveServerCiphMsg\n");
		return 0;
	}
	bufflen = recibir(scnx->socket, &buff);

	msglen = decrypt_cbc256(scnx->ctx, scnx->key, scnx->iv, (const unsigned char*)buff,
			(unsigned char**)&text, bufflen);
	if(IERROR == strToSigMsgGS(msg, &msglen, &sigstr, &siglen, text, msglen)){
		fprintf(stdout, "Error: recived invalid message siglen %d msglen %d\n", siglen, msglen);
		return 0;
	}

	if(!verifySignGS(sigstr, scnx->grpkey, *msg, scnx->scheme))
		return 0;

	scnx->iv = realloc(scnx->iv, bufflen);
	memcpy(scnx->iv, buff, bufflen);
	if(scnx != NULL)
		free(scnx->lastsig);
	scnx->lastsig = sigstr;
	scnx->siglen = siglen;
	free(text);
	free(buff);
	return msglen;
}

int sendServerCiphMsg(Sconexion_t* scnx, const unsigned char* text, int textlen){
	int msglen = 0;
	char*  msg = NULL;
	if(scnx == NULL || scnx->socket == -1 || scnx->ctx == NULL || scnx->key == NULL || 
		scnx->iv == NULL || text == NULL || textlen < 1)
		return 0;
	
	msglen = encrypt_cbc256(scnx->ctx, scnx->key, scnx->iv, text, (unsigned char**)&msg, textlen);
	if(msglen <1)
		return 0;
	msglen = escribir(scnx->socket, msg, msglen);
	scnx->iv = realloc(scnx->iv, msglen);
	memcpy(scnx->iv, msg, msglen);

	free(msg);
	return msglen;
}


int reciveClientCiphMsg(Sconexion_t* scnx, char** msg){
	int bufflen = 0, msglen =0;
	char*  buff = NULL;
	if(scnx== NULL || scnx->socket == -1 || scnx->ctx == NULL || scnx->key == NULL || 
		scnx->iv == NULL || msg == NULL )
		return 0;
	bufflen = recibir(scnx->socket, &buff);
	if(bufflen <1)
		return 0;
	msglen = decrypt_cbc256(scnx->ctx, scnx->key, scnx->iv, (const unsigned char*)buff, 
		(unsigned char**)msg, bufflen);
	
	scnx->iv = realloc(scnx->iv, bufflen);
	memcpy(scnx->iv, buff, bufflen);
	
	free(buff);
	return msglen;
}

int revokeClient(Sconexion_t* scnx, groupsig_key_t *mgrkey, gml_t *gml, crl_t *crl, char* s_crlf){

	groupsig_signature_t* sig = NULL;
	message_t* sigmsg = NULL;

	sigmsg =  message_init();	
	memcpy(&sigmsg->length, scnx->lastsig, sizeof(uint64_t));
	sigmsg->bytes = malloc(sigmsg->length);
	memcpy(sigmsg->bytes, scnx->lastsig + sizeof(uint64_t), sigmsg->length);

	if((sig = groupsig_signature_import(scnx->scheme, GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL, sigmsg)) ==  NULL){
		printf("Error: failed to import the signature.\n" );
		return IERROR;	
	}

	revokeSigGS(sig, scnx->grpkey, mgrkey, gml, crl, scnx->scheme, s_crlf);
	message_free(sigmsg);
	groupsig_signature_free(sig);
	return IOK;

}


int clientInitSConexion(Sconexion_t* scnx){
	EVP_PKEY* DHkey = NULL, *DHpeerKey = NULL;
	EVP_PKEY_CTX* pctxDH = NULL;
	char* sigstr = NULL, *msg = NULL, *buff = NULL;
	int siglen = 0, msglen = 0, bufflen = 0;

	if(scnx == NULL || scnx->socket < 0 || scnx->keyRSA == NULL || scnx->grpkey == NULL || 
		scnx->memkey ==  NULL){
		return -1;
	}
	OpenSSL_add_all_algorithms();
	groupsig_init(time(NULL));
	/*CHECK RSA MSG*/
	if(!(bufflen = reciveRSAsign(scnx->socket, scnx->keyRSA, (unsigned char**) &buff)))
		return -1;

	/*DERIVE AES KEY*/
	if (!msgToDHpubKey(&DHpeerKey, buff, bufflen)){
		return 0;
	}

	if(0 == genKeyFromParamsDH(&pctxDH,&DHkey, DHpeerKey)){
		return 0;		
	}
	free(buff); buff = NULL;

	scnx->key = deriveSharedSecretDH(DHkey, DHpeerKey);

	/*SEND SIGNED PUBKEY DH*/
	msglen = DHpubKeyToMsg(DHkey, &msg);
	siglen = signMsgGS(scnx->grpkey, scnx->memkey, scnx->scheme, msg, &sigstr);
	bufflen = sigMsgToStrGS(msg, msglen, sigstr, siglen, &buff);

	escribir(scnx->socket, buff, bufflen);

	free(buff);
	free(msg);
	free(sigstr);
	
	EVP_PKEY_free(DHkey);
	EVP_PKEY_free(DHpeerKey);
	EVP_PKEY_CTX_free(pctxDH);



	/*CHECK RSA MSG*/
	if(!(bufflen = reciveRSAsign(scnx->socket, scnx->keyRSA, (unsigned char**) &buff)))
		return -1;

	/*DERIVE AES IV*/
	if (!msgToDHpubKey(&DHpeerKey, buff, bufflen)){
		return 0;
	}

	if(0 == genKeyFromParamsDH(&pctxDH, &DHkey, DHpeerKey)){
		return 0;		
	}
	free(buff); buff = NULL;

	scnx->iv = deriveSharedSecretDH(DHkey, DHpeerKey);

	/*SEND SIGNED PUBKEY DH*/
	msglen = DHpubKeyToMsg(DHkey, &msg);
	siglen = signMsgGS(scnx->grpkey, scnx->memkey, scnx->scheme, msg, &sigstr);
	bufflen = sigMsgToStrGS(msg, msglen, sigstr, siglen, &buff);

	escribir(scnx->socket, buff, bufflen);

	free(buff);
	free(msg);
	free(sigstr);
	
	EVP_PKEY_free(DHkey);
	EVP_PKEY_free(DHpeerKey);
	EVP_PKEY_CTX_free(pctxDH);

	return 1;
}


int serverInitSConexion(Sconexion_t* scnx, groupsig_key_t *mgrkey, crl_t* crl, gml_t* gml){
	EVP_PKEY* paramsDH = NULL, *DHkey = NULL, *DHpeerKey = NULL;
	EVP_PKEY_CTX* pctxDH = NULL;
	char* sigstr = NULL, *msg = NULL, *buff = NULL;
	int siglen = 0, msglen = 0, bufflen = 0;

	if(scnx == NULL || scnx->socket < 0 || scnx->keyRSA == NULL || scnx->grpkey == NULL){
		return -1;
	}
	OpenSSL_add_all_algorithms();
	/*DH KEY PARAMS FOR AES KEY*/	
	getParamsIniDH(&paramsDH);
	genKeyFromParamsDH(&pctxDH, &DHkey, paramsDH);

	/*SIGN RSA MSG*/

	msglen = DHpubKeyToMsg(DHkey, &msg);
	if(sendRSAsign(scnx->socket, scnx->keyRSA, (const unsigned char*)msg, msglen) == 0){
		return 0;
	}
	free(msg);
	msg = NULL;
	msglen = 0;
	bufflen = recibir(scnx->socket, &buff);
	if(bufflen < 1)
		return 0;

	/*CHECK GS MSG*/
	strToSigMsgGS(&msg, &msglen, &sigstr, &siglen, buff, bufflen);
	if(!verifySignGS(sigstr, scnx->grpkey, msg, scnx->scheme))
		return 0;

	if(traceSignGS(sigstr, scnx->grpkey, mgrkey, crl, gml, scnx->scheme)){
		fprintf(stderr, "Clave revocada.\n");
		return 0;
	}

	/*DERIVE AES KEY*/
	msgToDHpubKey(&DHpeerKey, msg, msglen);
	scnx->key = deriveSharedSecretDH(DHkey, DHpeerKey);

	free(msg); msg = NULL;
	free(sigstr); sigstr = NULL;
	free(buff); buff = NULL;

	EVP_PKEY_free(paramsDH); paramsDH = NULL;
	EVP_PKEY_free(DHkey); DHkey = NULL;
	EVP_PKEY_free(DHpeerKey); DHpeerKey = NULL;
	EVP_PKEY_CTX_free(pctxDH); pctxDH = NULL;



	/*DH KEY PARAMS FOR AES KEY*/	
	getParamsIniDH(&paramsDH);
	genKeyFromParamsDH(&pctxDH, &DHkey, paramsDH);

	/*SIGN RSA MSG*/

	msglen = DHpubKeyToMsg(DHkey, &msg);
	if(sendRSAsign(scnx->socket, scnx->keyRSA, (const unsigned char*)msg, msglen) == 0){
		return 0;
	}
	free(msg);
	msg = NULL;
	msglen = 0;
	bufflen = recibir(scnx->socket, &buff);
	if(bufflen < 1)
		return 0;

	/*CHECK GS MSG*/
	strToSigMsgGS(&msg, &msglen, &sigstr, &siglen, buff, bufflen);
	if(!verifySignGS(sigstr, scnx->grpkey, msg, scnx->scheme))
		return 0;

	/*DERIVE AES IV*/
	msgToDHpubKey(&DHpeerKey, msg, msglen);
	scnx->iv = deriveSharedSecretDH(DHkey, DHpeerKey);

	free(msg); msg = NULL;
	free(sigstr); sigstr = NULL;
	free(buff); buff = NULL;

	EVP_PKEY_free(paramsDH); paramsDH = NULL;
	EVP_PKEY_free(DHkey); DHkey = NULL;
	EVP_PKEY_free(DHpeerKey); DHpeerKey = NULL;
	EVP_PKEY_CTX_free(pctxDH); pctxDH = NULL;

	return 1;

}


int crlRelaod(Sconexion_t* scnx, crl_t** crl, char* s_crl){

	crl_free(*crl); *crl = NULL;
	*crl = crl_import(scnx->scheme, CRL_FILE, s_crl);
	if(*crl == NULL){
		fprintf(stderr, "Error: invalid crl %s.\n", s_crl);
		return 0;
	}
	
	return 1;

}