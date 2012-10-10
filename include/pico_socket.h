#ifndef _INCLUDE_PICO_SOCKET
#define _INCLUDE_PICO_SOCKET
#include "pico_queue.h"
#include "pico_addressing.h"


struct pico_socket {
  struct pico_trans trans;
  struct pico_protocol *proto;
  struct pico_protocol *net;

  union {
    struct pico_ip4 ip4;
    struct pico_ip6 ip6;
  } local_addr;

  union {
    struct pico_ip4 ip4;
    struct pico_ip6 ip6;
  } remote_addr;

  struct pico_queue q_in;
  struct pico_queue q_out;

  uint16_t state;

};

#define PICO_SOCKET_STATE_UNDEFINED       0x0000
#define PICO_SOCKET_STATE_OPEN_LOCAL      0x0001
#define PICO_SOCKET_STATE_OPEN_REMOTE     0x0002
#define PICO_SOCKET_STATE_BOUND           0x0004
#define PICO_SOCKET_STATE_CONNECTED       0x0008
#define PICO_SOCKET_STATE_LISTENING       0x0010
#define PICO_SOCKET_STATE_CLOSING         0x0020

#define PICO_SOCKET_SHUTDOWN_WRITE 0x01
#define PICO_SOCKET_SHUTDOWN_READ  0x02



struct pico_socket *pico_socket_open(uint16_t net, uint16_t proto);

int pico_socket_read(struct pico_socket *s, void *buf, int len);
int pico_socket_write(struct pico_socket *s, void *buf, int len);

int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t dport);
int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *sport);

int pico_socket_connect(struct pico_socket *s, void *srv_addr, uint16_t dport);
int pico_socket_listen(struct pico_socket *s);
struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *sport);

int pico_socket_setoption(struct pico_socket *s, int option, void *value);
int pico_socket_getoption(struct pico_socket *s, int option, void *value);

int pico_socket_shutdown(struct pico_socket *s, int mode);
int pico_socket_close(struct pico_socket *s);


#endif
