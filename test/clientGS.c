#include "../include/funcionesGS.h"
#include "../include/conexion.h"
#include <netdb.h>


int main(int argc, char const **argv){
	struct addrinfo hints, *res;
	char* buff;
	int sockfd;
	int msglen, siglen;
	char* msgstr,* sigstr;
	groupsig_key_t *grpkey;
	char s_grpkey[] = ".fg/group/grp.key";

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	uint8_t scheme = -1;
	int key_format = -1;


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


	/*Comenzamos la conexion TCP*/
	if(0!=getaddrinfo("127.0.0.1", "8080", &hints, &res)){
		printf("No se pudo conectar con el servidor\n");
		return 0;
	}
	sockfd=abrirSocketTCP();
	if(sockfd==-1){
		return 0;
	}
	if(-1==abrirConnect(sockfd, *(res->ai_addr))){
		  
		return 0;
	}

	printf("Esperando firma.\n");
	msglen = recibir(sockfd, &buff);
	BIO_dump_fp(stdout, (const char*) buff, msglen);
	printf("msglen:%d\n", msglen);

	strToSigMsgGS(&msgstr, &msglen, &sigstr, &siglen, buff, msglen);
	printf("msglen:%d\n", msglen);
	printf("siglen:%d\n", siglen);

	printf("%d\n",  verifySignGS(sigstr, grpkey, msgstr, scheme));
	printf("%s\n", msgstr);
	
	close(sockfd);
	return 0;
}