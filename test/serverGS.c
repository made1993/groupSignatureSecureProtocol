#include "../include/funcionesGS.h"
#include "../include/conexion.h"

int main(int argc, char const **argv){

	int key_format = 0;
	uint8_t scheme = -1;
	char s_grpkey[] = ".fg/group/grp.key";
	char s_memkey[] = ".fg/members/0.key";
	char msgstr[] = "Hello World";
	char * sigstr = NULL, *dest = NULL;
	int size;
	groupsig_key_t *grpkey = NULL, *memkey = NULL;
	


	if((groupsig_get_code_from_str(&scheme, "CPY06")) == IERROR) {
		fprintf(stderr, "Error: Wrong scheme\n");
		return IERROR;
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
		return IERROR;
	}

	groupsig_init(time(NULL));

	if(!(grpkey = groupsig_grp_key_import(scheme, key_format, s_grpkey))) {
		fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
		return IERROR;
	}

	if(!(memkey = groupsig_mem_key_import(scheme,	key_format, s_memkey))) {
		fprintf(stderr, "Error: invalid member key %s.\n", s_memkey);
		return IERROR;
	}
	int siglen = 0, msglen = 0, res = 0, i = 0;
	char* signture = NULL, *message = NULL;
	size = signMsgGS(grpkey, memkey, scheme, msgstr, &sigstr);
	printf("Tamaño del mensaje: %d\n", size);
	size = sigMsgToStrGS(msgstr, strlen(msgstr)+1, sigstr, size, &dest);
	BIO_dump_fp(stdout, (const char*) dest, size);
	
	printf("3\n");
	strToSigMsgGS(&message, &msglen, &signture, &siglen, dest, size);
	res = verifySignGS(signture, grpkey, message, scheme);
	printf("i: %d\tres: %d\n", i++, res);
	groupsig_grp_key_free(grpkey); grpkey = NULL;
	groupsig_mem_key_free(memkey); memkey = NULL;
	groupsig_clear();

	free(sigstr);
	free(dest);
	free(signture);
	free(message);

	return 0;
}