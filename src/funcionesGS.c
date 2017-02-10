#include "../include/funcionesGS.h"


int import_manager(groupsig_key_t** grpkey, groupsig_key_t** mgrkey, crl_t** crl, gml_t** gml, 
			char* grpkeyf, char* mgrkeyf, char* crlf, char* gmlf, int scheme){

	int key_format = -1;

	if(grpkeyf == NULL || mgrkeyf == NULL || gmlf == NULL || crlf == NULL ||
		strlen(grpkeyf) < 1 || strlen(mgrkeyf) < 1 || strlen(crlf) < 1 || strlen(gmlf) < 1){
		return 0;
	}
	switch(scheme) {
	case GROUPSIG_KTY04_CODE:
		key_format = GROUPSIG_KEY_FORMAT_FILE_NULL_B64;
		break;
	case GROUPSIG_BBS04_CODE:

	case GROUPSIG_CPY06_CODE:

		key_format = GROUPSIG_KEY_FORMAT_FILE_NULL;
		break;
	default:
		fprintf(stderr, "Error: unknown scheme.\n");
		return 0;
	}
	
	*grpkey = NULL; *mgrkey = NULL; *crl = NULL; *gml =  NULL;

	*grpkey = groupsig_grp_key_import(scheme, key_format, grpkeyf);
	if(*grpkey == NULL){
		fprintf(stderr, "Error: invalid grpkey %s.\n", grpkeyf);
		return 0;
	}
		
	*mgrkey = groupsig_mgr_key_import(scheme, key_format, mgrkeyf);
	if(*mgrkey == NULL){
		fprintf(stderr, "Error: invalid mgrkey %s.\n", mgrkeyf);
		return 0;
	}

	*crl = crl_import(scheme, CRL_FILE, crlf);
	if(*crl == NULL){
		fprintf(stderr, "Error: invalid crl %s.\n", crlf);
		return 0;
	}

	*gml = gml_import(scheme, GML_FILE, gmlf);
	if(*gml == NULL){
		fprintf(stderr, "Error: invalid gml %s.\n", gmlf);
		return 0;
	}

	return 1;

}

int import_member(groupsig_key_t** grpkey, groupsig_key_t** memkey, char* grpkeyf, char* memkeyf, int scheme){
	
	int key_format = -1;

	if(grpkeyf == NULL || memkeyf == NULL || strlen(grpkeyf) < 1 || strlen(memkeyf) < 1 ){
		return 0;
	}
	switch(scheme) {
	case GROUPSIG_KTY04_CODE:
		key_format = GROUPSIG_KEY_FORMAT_FILE_NULL_B64;
		break;
	case GROUPSIG_BBS04_CODE:

	case GROUPSIG_CPY06_CODE:

		key_format = GROUPSIG_KEY_FORMAT_FILE_NULL;
		break;
	default:
		fprintf(stderr, "Error: unknown scheme.\n");
		return 0;
	}
	
	*grpkey = NULL; *memkey = NULL;

	*grpkey = groupsig_grp_key_import(scheme, key_format, grpkeyf);
	if(*grpkey == NULL){
		fprintf(stderr, "Error: invalid grpkey %s.\n", grpkeyf);
		return 0;
	}
	*memkey = groupsig_mem_key_import(scheme, key_format, memkeyf);
	if(*memkey == NULL){
		fprintf(stderr, "Error: invalid memkey %s.\n", memkeyf);
		return 0;
	}

	return 1;
}


int signMsgGS(groupsig_key_t* grpkey, groupsig_key_t* memkey, uint8_t scheme,
				char *msgstr, char** sigstr){
	message_t* msg = NULL, *sigmsg =  NULL;
	groupsig_signature_t* sig = NULL;
	int size;
	if(grpkey == NULL || memkey == NULL || msgstr == NULL || sigstr == NULL){
		fprintf(stderr, "Error: failed to sign a message.\n");
		return IERROR;
	}
	*sigstr = NULL;
	msg = message_from_string(msgstr);
	if(msg == NULL){
		fprintf(stderr, "Error: failed to initialize the message object.\n");
		return IERROR;
	}

	if(!(sig = groupsig_signature_init(scheme))) {
		fprintf(stderr, "Error: failed to initialize the group signature object.\n");
		return IERROR;
	}

	if(groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX) == IERROR){
		fprintf(stderr, "Error: signing failure.\n");
		return IERROR;
	}


	
	sigmsg = message_init();
	groupsig_signature_export(sig, GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL, sigmsg);	
	groupsig_signature_free(sig);

	*sigstr = malloc(sigmsg->length + sizeof(uint64_t));
	memcpy(*sigstr, &sigmsg->length, sizeof(uint64_t));
	memcpy((*sigstr) + sizeof(uint64_t), sigmsg->bytes, sigmsg->length);
	/*TODO quiza haya que meter el esquema que se usa*/
	
	size = (int)sigmsg->length + sizeof(uint64_t);
	message_free(msg);
	message_free(sigmsg);
	return size;
}

int verifySignGS(char* sigstr, groupsig_key_t *grpkey, char* msgstr, uint8_t scheme){

	uint8_t bool = 0;
	groupsig_signature_t* sig = NULL;
	message_t *msg = NULL, *sigmsg = NULL;

	if(sigstr == NULL || grpkey == NULL || msgstr == NULL){
		fprintf(stderr, "Error: NULL input.\n");
		return IERROR;
	}
	
	sigmsg =  message_init();	
	memcpy(&sigmsg->length, sigstr, sizeof(uint64_t));
	sigmsg->bytes = malloc(sigmsg->length);
	memcpy(sigmsg->bytes, sigstr + sizeof(uint64_t), sigmsg->length);

	if((sig = groupsig_signature_import(scheme, GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL, sigmsg)) ==  NULL){
		printf("Error: failed to import the signature.\n" );
		return IERROR;	
	}

	msg = message_from_string(msgstr);
	if(msg == NULL){
		fprintf(stderr, "Error: failed to initialize the message object.\n");
		return IERROR;
	}
	if(groupsig_verify(&bool, sig, msg, grpkey) == IERROR) {
		fprintf(stderr, "Error: verification failure.\n");
		return IERROR;
	}
	message_free(msg);
	message_free(sigmsg);
	groupsig_signature_free(sig);
	return bool;
}


int traceSignGS(char* sigstr, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, crl_t* crl,
			gml_t* gml, uint8_t scheme){
	uint8_t bool = 0;
	message_t * sigmsg = NULL;
	groupsig_signature_t* sig = NULL;

		if(sigstr == NULL || grpkey == NULL || mgrkey == NULL || 
			crl == NULL || gml == NULL){
		fprintf(stderr, "Error: NULL input.\n");
		return IERROR;
	}

	sigmsg =  message_init();	
	memcpy(&sigmsg->length, sigstr, sizeof(uint64_t));
	sigmsg->bytes = malloc(sigmsg->length);
	memcpy(sigmsg->bytes, sigstr + sizeof(uint64_t), sigmsg->length);

	if((sig = groupsig_signature_import(scheme, GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL, sigmsg)) ==  NULL){
		printf("Error: failed to import the signature.\n" );
		return IERROR;	
	}

	if(groupsig_trace(&bool, sig, grpkey, crl, mgrkey, gml) == IERROR) {
		fprintf(stderr, "Error: failed to trace the signature.\n");
		return 1;
    }
    message_free(sigmsg);
	groupsig_signature_free(sig);
    return bool;
}


int revokeSigGS(groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
			 gml_t *gml,  crl_t *crl, uint8_t scheme, char *s_crl){
	identity_t *id = NULL;
	int rc = 0;
	trapdoor_t *trap = NULL;
	if (sig == NULL || grpkey == NULL || mgrkey == NULL || gml == NULL || crl == NULL)
		return IERROR;

	if(!(id = identity_init(scheme))){
		fprintf(stderr, "Error creating identity.\n");
		return IERROR;
	}
	if((rc = groupsig_open(id, NULL, NULL, sig, grpkey, mgrkey, gml)) == IERROR) {
		fprintf(stderr, "Error opening signature.\n");
		return IERROR;
    }
	if(!(trap = trapdoor_init(scheme))) {
		fprintf(stderr, "Error creating trapdoor.\n");
		return IERROR;
	}

	if(groupsig_reveal(trap, crl, gml, *(uint64_t *) id->id) == IERROR) {
		fprintf(stderr, "Error in reveal.\n");
		return IERROR;
	}

	if(crl_export(crl, s_crl, CRL_FILE) == IERROR) {
		fprintf(stderr, "Error exporting CRL.\n");
		return IERROR;
	}
	identity_free(id); id = NULL;
	trapdoor_free(trap); trap = NULL;

	return IOK;
}

int sigMsgToStrGS(char * msgstr, int msglen, char* sigstr, int siglen, char** dst){
	int size = -1;
	if(msgstr == NULL || msglen < 1 || sigstr == NULL || siglen < 1 || dst == NULL){
		fprintf(stderr, "Error: NULL input.\n");
		return IERROR;
	}
	*dst = NULL;
	size = msglen + siglen + sizeof(int)*2;
	*dst = malloc (size);


	memcpy(*dst, &siglen, sizeof(int));
	memcpy((*dst) + sizeof(int), sigstr, siglen);

	memcpy((*dst) + sizeof(int) + siglen, &msglen, sizeof(int));
	memcpy((*dst) + sizeof(int)*2 + siglen, msgstr, msglen);

	return size;
}

int strToSigMsgGS(char** msgstr, int *msglen, char** sigstr, int* siglen, char* src, int srclen){

	if(msgstr == NULL || msglen == NULL || sigstr == NULL || siglen == NULL || src == NULL){
		fprintf(stdout, "Error: NULL input.\n");
		return IERROR;
	}
	memcpy(siglen, src, sizeof(int));
	if(*siglen > srclen - sizeof(int)){
		fprintf(stdout, "Error: ivalid size of signature %d\n", *siglen);
		return IERROR;
	}
	*sigstr = malloc(*siglen);
	memcpy(*sigstr, src + sizeof(int), *siglen);

	memcpy(msglen, src + sizeof(int) + *siglen, sizeof(int));
	if(*msglen > srclen - *siglen - sizeof(int)*2){
		fprintf(stdout, "Error: ivalid size of message %d\n", *msglen);
		return IERROR;
	}
	*msgstr = malloc(*msglen);
	memcpy(*msgstr, src + sizeof(int)*2 + *siglen, *msglen);
	
	return IOK;
}

