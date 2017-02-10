#include "../include/funcionesRSA.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>
#include <getopt.h>

int main(){
	struct addrinfo hints, *res;
	char* buff;
	
	EVP_PKEY* pubkey;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	int sockfd, status;

	OpenSSL_add_all_algorithms();
	/*Comenzamos la conexion TCP*/
	RSAfileToPubKey(&pubkey, "pubkey.pub");
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


	printf("esperando clave\n");
	//reciveRSAkey(sockfd, &pubkey);
	printf("recibida clave\n");
	status = reciveRSAsign(sockfd, pubkey, (unsigned char**) &buff);
	printf("recibida firma\n");
	printf("%d\n", status);
	printf("%s\n", buff);
	close(sockfd);
	return 1;
}