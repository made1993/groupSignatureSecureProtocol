#ifndef FUNCIONESGS_H
#define FUNCIONESGS_H

#include <groupsig/groupsig.h>
#include <groupsig/gml.h>
#include <groupsig/crl.h>
#include <time.h>

#include <openssl/pem.h>
#include <openssl/evp.h>

int import_manager(groupsig_key_t** grpkey, groupsig_key_t** mgrkey, crl_t** crl, gml_t** gml, 
			char* grpkeyf, char* mgrkeyf, char* crlf, char* gmlf, int scheme);

int import_member(groupsig_key_t** grpkey, groupsig_key_t** memkey, char* grpkeyf, char* memkeyf, int scheme);

int signMsgGS(groupsig_key_t* grpkey, groupsig_key_t* memkey, uint8_t scheme, char *msgstr, char** sigstr);

int verifySignGS(char* sigstr, groupsig_key_t *grpkey, char* msgstr, uint8_t scheme);

int traceSignGS(char* sigstr, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, crl_t* crl, gml_t* gml, uint8_t scheme);
int revokeSigGS(groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
			 gml_t *gml,  crl_t *crl, uint8_t scheme, char *s_crl);

int sigMsgToStrGS(char * msgstr, int msglen, char* sigstr, int siglen, char** dst);

int strToSigMsgGS(char** msgstr, int *msglen, char** sigstr, int* siglen, char* src, int srclen);

#endif