#include "../include/funcionesRSA.h"

#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main(){
	EVP_PKEY* privKey, * pubKey;
	const unsigned char msg[] = "hello friend"; 
	int sockfd, w;
	struct sockaddr_in ip4addr;
	int socketcli;
	
	OpenSSL_add_all_algorithms();
	//generateKeysRSA(&privKey, &pubKey);
	
	//RSApubKeyToFile(pubKey, "pubKey.txt", &w);

	//RSAprivKeyToFile(pubKey, "privKey.txt", &w);
	printf("ret->%d\n", RSAfileToPrivKey(&privKey, "privkey.pem"));
	sockfd = abrirSocketTCP();
	abrirBind(sockfd, 8080);
	abrirListen(sockfd);
	printf("ESPERANDO CLIENTE\n");
	socketcli=aceptar(sockfd, ip4addr);
	
	//sendRSAkey(socketcli, pubKey);
	printf("CLAVE RSA enviada\n");
	printf( "%d\n",sendRSAsign(socketcli, privKey, msg, strlen((char*) msg)+1));
	printf("firma enviada\n");
	close(socketcli);
	close(sockfd);
	return 0;
}