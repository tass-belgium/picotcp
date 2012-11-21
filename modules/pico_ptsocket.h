#ifndef _INCLUDE_PICO_PTSOCKET
#define _INCLUDE_PICO_PTSOCKET
#include "pico_config.h"
#include "pico_socket.h"

#include <pthread.h>

#define PF_INET     2
#define PF_INET6    10
#define AF_INET     PF_INET
#define AF_INET6    PF_INET6

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2


int pico_ptsocket(int domain, int type, int protocol);
int pico_ptbind(int sockfd, void *addr, int addrlen);
int pico_ptconnect(int sockfd, void *addr, int addrlen);
int pico_ptaccept(int sockfd, void *addr, int *addrlen);
int pico_ptlisten(int sockfd, int backlog);
int pico_ptrecvfrom(int sockfd, void *buf, int len, int flags, void *addr, int *addrlen);
#define pico_ptrecv(s,b,l,f) pico_ptrecvfrom(s,b,l,f,NULL,NULL)
#define pico_ptread(s,b,l) pico_ptrecvfrom(s,b,l,0,NULL,NULL)
int pico_ptsendto(int sockfd, void *buf, int len, int flags, void *addr, int addrlen);
#define pico_ptsend(s,b,l,f) pico_ptsendto(s,b,l,f,NULL,0)
#define pico_ptwrite(s,b,l) pico_ptsendto(s,b,l,0,NULL,0)
int pico_ptclose(int sockfd);
int pico_ptshutdown(int sockfd, int how);

#endif
