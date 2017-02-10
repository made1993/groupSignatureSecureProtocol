#ifndef _SOCKET_H
#define _SOCKET_H

#include <string.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>

#define MAX_MSG_LEN 8096
#define LAST_MSG 0
#define MORE_MSG 1
typedef struct argumentos{
	char direccion[20];
	char strPuerto[20];
	char *archivo;
	int intPuerto;
}ARGUMENTOS;

struct argumentos args;
int abrirSocketTCP();
int abrirSocketUDP();
int abrirBind(int sockfd,int puerto);
int aceptar(int sockfd, struct sockaddr_in ip4addr);
int abrirConnect(int sockfd, struct sockaddr ip4addr);
int abrirListen(int sockfd);
int recibir(int sockfd,char **buf);
int escribir(int sockfd,char *msg, int mlen);
char* atoIp(char* str);
uint8_t obtenerIPInterface(char * interface, uint8_t* retorno);

#endif
