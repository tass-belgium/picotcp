/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

 *********************************************************************/
#ifndef _INCLUDE_PICO_PTSOCKET
#define _INCLUDE_PICO_PTSOCKET
#include "pico_config.h"
#include "pico_socket.h"

#include <pthread.h>
#ifndef PF_INET
#define PF_INET     2
#define PF_INET6    10
#define AF_INET     PF_INET
#define AF_INET6    PF_INET6

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2
#endif


int pico_ptsocket(int domain, int type, int protocol);
int pico_ptbind(int sockfd, void *addr, int addrlen);
int pico_ptconnect(int sockfd, void *addr, int addrlen);
int pico_ptaccept(int sockfd, void *addr, int *addrlen);
int pico_ptlisten(int sockfd, int backlog);
int pico_ptrecvfrom(int sockfd, void *buf, int len, int flags, void *addr, int *addrlen);
int pico_ptread(int sockfd, void *buf, int len);
#define pico_ptrecv(s, b, l, f) pico_ptread(s, b, l)
int pico_ptsendto(int sockfd, void *buf, int len, int flags, void *addr, int addrlen);
int pico_ptwrite(int sockfd, void *buf, int len);
#define pico_ptsend(s, b, l, f) pico_ptwrite(s, b, l)
int pico_ptclose(int sockfd);
int pico_ptshutdown(int sockfd, int how);
int pico_ptstart(void);

#endif
