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


int socket(int domain, int type, int protocol);
int bind(int sockfd, void *addr, int addrlen);
int connect(int sockfd, void *addr, int addrlen);
int accept(int sockfd, void *addr, int *addrlen);
int listen(int sockfd, int backlog);
int recvfrom(int sockfd, void *buf, int len, int flags, void *addr, int *addrlen);
#define recv(s,b,l,f) recvfrom(s,b,l,f,NULL,NULL)
#define read(s,b,l) recvfrom(s,b,l,0,NULL,NULL)
int sendto(int sockfd, void *buf, int len, int flags, void *addr, int addrlen);
#define send(s,b,l,f) sendto(s,b,l,f,NULL,0)
#define write(s,b,l) sendto(s,b,l,0,NULL,0)
int close(int sockfd);
int shutdown(int sockfd, int how);

#endif
