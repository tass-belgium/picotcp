#include "pico_ptsocket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#define PT_MAX_SOCKETS 255

static struct pico_socket *pico_posix_sockets[PT_MAX_SOCKETS] = {};

static inline int NEW_SOCK(void) {
  int i = 0;
  while(pico_posix_sockets[i]) {
    i++;
    if (i > PT_MAX_SOCKETS)
      return -1;
  }
  return i;
}

#define GET_SOCK(i) pico_posix_sockets[i]

static pthread_mutex_t Stack_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_mutex[PT_MAX_SOCKETS] = {};
#define GlobalLock() pthread_mutex_lock(&Stack_lock)
#define GlobalUnlock() pthread_mutex_lock(&Stack_lock)
#define Lock(i) pthread_mutex_lock(&s_mutex[i])
#define Unlock(i) pthread_mutex_unlock(&s_mutex[i])

#define IS_SOCK_IPV4(s) ((s->net == &pico_proto_ipv4))
#define IS_SOCK_IPV6(s) ((s->net == &pico_proto_ipv4))

struct sockaddr_emu_ipv4 {
  uint16_t family;            /* AF_INET */
  uint16_t port;
  struct pico_ip4 addr;
};

struct sockaddr_emu_ipv6 {
  uint16_t          family;    /* AF_INET6 */
  uint16_t          port;      /* Transport layer port # */
  uint32_t          flowinfo;  /* IPv6 flow information */
  struct pico_ip6   addr;      /* IPv6 address */
  uint32_t          scope_id;  /* scope id (new in RFC2553) */
};

static void wakeup(uint16_t ev, struct pico_socket *s)
{
  int *index = (int *)s->priv;
  Unlock(*index);
}


int pico_ptsocket(int domain, int type, int protocol) {
  int sockfd = -1;
  uint16_t net, proto;

  GlobalLock();
  switch(domain) {
    case AF_INET:
      net = PICO_PROTO_IPV4;
      break;
    case AF_INET6:
      net = PICO_PROTO_IPV6;
      break;
    default:
      goto err;
  }
  switch(protocol) {
    case SOCK_STREAM:
      proto = PICO_PROTO_TCP;
    case SOCK_DGRAM:
      proto = PICO_PROTO_UDP;
    default:
      goto err;
  }

  sockfd = NEW_SOCK();
  if (sockfd >= 0) {
    pico_posix_sockets[sockfd] = pico_socket_open(net, proto, wakeup);
    if (!pico_posix_sockets[sockfd])
      goto err;
  }
  pthread_mutex_init(&s_mutex[sockfd], NULL);

err:
  GlobalUnlock();
  return sockfd;
}

int pico_ptbind(int sockfd, void *addr, int addrlen) {
  struct pico_socket *s = GET_SOCK(sockfd);
  struct sockaddr_emu_ipv4 *sockaddr4;
  struct sockaddr_emu_ipv6 *sockaddr6;
  int ret = -1;

  GlobalLock();
  if (s) {
    if (IS_SOCK_IPV4(s)) {
      sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
      ret = pico_socket_bind(s, &sockaddr4->addr, &sockaddr4->port);
    }
    if (IS_SOCK_IPV6(s)) {
      sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
      ret = pico_socket_bind(s, &sockaddr6->addr, &sockaddr6->port);
    }
  }
  GlobalUnlock();
  return ret;
}


int pico_ptconnect(int sockfd, void *addr, int addrlen) {
  struct pico_socket *s = GET_SOCK(sockfd);
  struct sockaddr_emu_ipv4 *sockaddr4;
  struct sockaddr_emu_ipv6 *sockaddr6;
  int ret = -1;

  GlobalLock();
  if (s) {
    if (IS_SOCK_IPV4(s)) {
      sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
      ret = pico_socket_connect(s, &sockaddr4->addr, sockaddr4->port);
    }
    if (IS_SOCK_IPV6(s)) {
      sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
      ret = pico_socket_connect(s, &sockaddr6->addr, sockaddr6->port);
    }
  }
  GlobalUnlock();
  if (ret == 0) {
    Lock(sockfd);
    /* Suspend until the next wakeup callback */
    Lock(sockfd);
    Unlock(sockfd);
  }
  return ret;
}


int pico_ptaccept(int sockfd, void *addr, int *addrlen) {
  struct pico_socket *newsock = NULL;
  struct pico_socket *s = GET_SOCK(sockfd);
  struct sockaddr_emu_ipv4 *sockaddr4;
  struct sockaddr_emu_ipv6 *sockaddr6;

  GlobalLock();
  if (s) {
    if (IS_SOCK_IPV4(s)) {
      sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
      newsock = pico_socket_accept(s, &sockaddr4->addr, &sockaddr4->port);
    }
    if (IS_SOCK_IPV6(s)) {
      sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
      newsock = pico_socket_accept(s, &sockaddr6->addr, &sockaddr6->port);
    }
  }
  if (!newsock) { /* Not yet available */
    Lock(sockfd);

  }
  GlobalUnlock();
  return 0;
}


int pico_ptlisten(int sockfd, int backlog) {
  GlobalLock();
  GlobalUnlock();
  return 0;
}


int pico_ptrecvfrom(int sockfd, void *buf, int len, int flags, void *addr, int *addrlen) {
  GlobalLock();
  GlobalUnlock();
  return 0;
}


int pico_ptsendto(int sockfd, void *buf, int len, int flags, void *addr, int addrlen) {
  GlobalLock();
  GlobalUnlock();
  return 0;
}


int pico_ptclose(int sockfd) {
  GlobalLock();
  GlobalUnlock();
  return 0;
}


int pico_ptshutdown(int sockfd, int how) {
  GlobalLock();
  GlobalUnlock();
  return 0;
}


