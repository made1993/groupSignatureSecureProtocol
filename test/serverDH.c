#include "../include/funcionesDH.h"

int main(){
	EVP_PKEY* dhkey, * params, * pubKey;
	EVP_PKEY_CTX* ctx;
	char* msg;
	unsigned char *skey;

	int msglen;
	int sockfd;
	struct sockaddr_in ip4addr;
	int socketcli;	

	getParamsIniDH(&params);
	genKeyFromParamsDH(&ctx, &dhkey, params);

	sockfd = abrirSocketTCP();
	abrirBind(sockfd, 8080);
	abrirListen(sockfd);
	printf("ESPERANDO CLIENTE\n");
	socketcli=aceptar(sockfd, ip4addr);
	
	msglen = DHpubKeyToMsg(dhkey, &msg);
	escribir(socketcli, msg, msglen);
	free(msg);
	msg =  NULL;

	msglen = recibir(socketcli, &msg);
	msgToDHpubKey(&pubKey, msg, msglen);
	skey = deriveSharedSecretDH(dhkey, pubKey);

	BIO_dump_fp(stdout, (const char*) skey, 256);
	
	close(socketcli);
	close(sockfd);
	return 0;
}