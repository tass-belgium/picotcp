#ifndef _INCLUDE_PICO_SOCKET
#define _INCLUDE_PICO_SOCKET
#include "pico_queue.h"
#include "pico_addressing.h"
#include "pico_config.h"
#include "rb.h"

//#define PICO_DEFAULT_SOCKETQ (8192 * 1024)
#define PICO_DEFAULT_SOCKETQ (8192)


struct pico_socket {
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

  uint16_t local_port;
  uint16_t remote_port;

  struct pico_queue q_in;
  struct pico_queue q_out;

  void (*wakeup)(uint16_t ev, struct pico_socket *s);


#ifdef PICO_SUPPORT_TCP
  /* For the TCP backlog queue */
  struct pico_socket *backlog;
  struct pico_socket *next;
  struct pico_socket *parent;
  int max_backlog;
#endif

  RB_ENTRY(pico_socket) node;

  uint16_t state;

};

#define PICO_SOCKET_STATE_UNDEFINED       0x0000
#define PICO_SOCKET_STATE_OPEN_LOCAL      0x0001
#define PICO_SOCKET_STATE_OPEN_REMOTE     0x0002
#define PICO_SOCKET_STATE_BOUND           0x0004
#define PICO_SOCKET_STATE_CONNECTED       0x0008
#define PICO_SOCKET_STATE_CLOSING         0x0010
#define PICO_SOCKET_STATE_CLOSED          0x0020

#ifdef PICO_SUPPORT_TCP
# define PICO_SOCKET_STATE_TCP                0xFF00
# define PICO_SOCKET_STATE_TCP_CLOSED         0x0100
# define PICO_SOCKET_STATE_TCP_LISTEN         0x0200
# define PICO_SOCKET_STATE_TCP_SYN_SENT       0x0300
# define PICO_SOCKET_STATE_TCP_SYN_RECV       0x0400
# define PICO_SOCKET_STATE_TCP_ESTABLISHED    0x0500
# define PICO_SOCKET_STATE_TCP_CLOSE_WAIT     0x0600
# define PICO_SOCKET_STATE_TCP_LAST_ACK       0x0700
# define PICO_SOCKET_STATE_TCP_FIN_WAIT1      0x0800
# define PICO_SOCKET_STATE_TCP_FIN_WAIT2      0x0900
# define PICO_SOCKET_STATE_TCP_CLOSING        0x0a00
# define PICO_SOCKET_STATE_TCP_TIME_WAIT      0x0b00
#endif

#define PICO_SOCKET_SHUTDOWN_WRITE 0x01
#define PICO_SOCKET_SHUTDOWN_READ  0x02
#define TCPSTATE(s) ((s)->state & PICO_SOCKET_STATE_TCP)

#define PICO_SOCK_EV_RD 0
#define PICO_SOCK_EV_WR 1
#define PICO_SOCK_EV_CONN 2
#define PICO_SOCK_EV_CLOSE 4
#define PICO_SOCK_EV_ERR 0xF0


struct pico_socket *pico_socket_open(uint16_t net, uint16_t proto, void (*wakeup)(uint16_t ev, struct pico_socket *s));

int pico_socket_read(struct pico_socket *s, void *buf, int len);
int pico_socket_write(struct pico_socket *s, void *buf, int len);

int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port);
int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *local_port);

int pico_socket_send(struct pico_socket *s, void *buf, int len);
int pico_socket_recv(struct pico_socket *s, void *buf, int len);

int pico_socket_bind(struct pico_socket *s, void *local_addr, uint16_t *port);
int pico_socket_connect(struct pico_socket *s, void *srv_addr, uint16_t remote_port);
int pico_socket_listen(struct pico_socket *s, int backlog);
struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port);

int pico_socket_setoption(struct pico_socket *s, int option, void *value);
int pico_socket_getoption(struct pico_socket *s, int option, void *value);

int pico_socket_shutdown(struct pico_socket *s, int mode);
int pico_socket_close(struct pico_socket *s);

#ifdef PICO_SUPPORT_IPV4
# define is_sock_ipv4(x) (x->net == &pico_proto_ipv4)
#else
# define is_sock_ipv4(x) (0)
#endif

#ifdef PICO_SUPPORT_IPV6
# define is_sock_ipv6(x) (x->net == &pico_proto_ipv6)
#else
# define is_sock_ipv6(x) (0)
#endif

#ifdef PICO_SUPPORT_UDP
# define is_sock_udp(x) (x->net == &pico_proto_udp)
#else
# define is_sock_udp(x) (0)
#endif

#ifdef PICO_SUPPORT_TCP
# define is_sock_tcp(x) (x->net == &pico_proto_tcp)
#else
# define is_sock_tcp(x) (0)
#endif

/* Interface towards transport protocol */
int pico_transport_process_in(struct pico_protocol *self, struct pico_frame *f);
struct pico_socket *pico_socket_clone(struct pico_socket *facsimile);
int pico_socket_add(struct pico_socket *s);

/* Socket loop */
int pico_sockets_loop(int loop_score);

#endif
