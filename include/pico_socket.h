/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_SOCKET
#define _INCLUDE_PICO_SOCKET
#include "pico_queue.h"
#include "pico_addressing.h"
#include "pico_config.h"
#include "pico_protocol.h"

#define PICO_DEFAULT_SOCKETQ (1024 * 128)
//#define PICO_DEFAULT_SOCKETQ (64 * 1024)
//#define PICO_DEFAULT_SOCKETQ (8192)


#define PICO_SHUT_RD   1
#define PICO_SHUT_WR   2
#define PICO_SHUT_RDWR 3


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
  uint16_t ev_pending;

	struct pico_device* dev;

  /* Private field. */
  int id;
  uint16_t state;
  uint16_t opt_flags;
};

struct pico_remote_duple {
  union {
    struct pico_ip4 ip4;
    struct pico_ip6 ip6;
  } remote_addr;

  uint16_t remote_port;
};


/* request struct for multicast socket opt */
struct pico_ip_mreq {
  struct pico_ip4 mcast_group_addr;
  struct pico_ip4 mcast_link_addr;
};

#define PICO_SOCKET_STATE_UNDEFINED       0x0000
#define PICO_SOCKET_STATE_SHUT_LOCAL      0x0001
#define PICO_SOCKET_STATE_SHUT_REMOTE     0x0002
#define PICO_SOCKET_STATE_BOUND           0x0004
#define PICO_SOCKET_STATE_CONNECTED       0x0008
#define PICO_SOCKET_STATE_CLOSING         0x0010
#define PICO_SOCKET_STATE_CLOSED          0x0020

# define PICO_SOCKET_STATE_TCP                0xFF00
# define PICO_SOCKET_STATE_TCP_UNDEF          0x00FF
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
# define PICO_SOCKET_STATE_TCP_ARRAYSIZ       0x0c

# define PICO_TCP_NODELAY                     1

# define PICO_SOCKET_OPT_TCPNODELAY           0x0000

# define PICO_IP_MULTICAST_IF                 32
# define PICO_IP_MULTICAST_TTL                33
# define PICO_IP_MULTICAST_LOOP               34
# define PICO_IP_ADD_MEMBERSHIP               35
# define PICO_IP_DROP_MEMBERSHIP              36

# define PICO_SOCKET_OPT_MULTICAST_LOOP       1

# define PICO_IP_DEFAULT_MULTICAST_TTL        1
# define PICO_IP_DEFAULT_MULTICAST_LOOP       1

#define PICO_SOCKET_SHUTDOWN_WRITE 0x01
#define PICO_SOCKET_SHUTDOWN_READ  0x02
#define TCPSTATE(s) ((s)->state & PICO_SOCKET_STATE_TCP)

#define PICO_SOCK_EV_RD 1
#define PICO_SOCK_EV_WR 2
#define PICO_SOCK_EV_CONN 4
#define PICO_SOCK_EV_CLOSE 8
#define PICO_SOCK_EV_FIN 0x10
#define PICO_SOCK_EV_ERR 0x80


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
struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *port);
int pico_socket_del(struct pico_socket *s);

int pico_socket_setoption(struct pico_socket *s, int option, void *value);
int pico_socket_getoption(struct pico_socket *s, int option, void *value);

int pico_socket_shutdown(struct pico_socket *s, int mode);
int pico_socket_close(struct pico_socket *s);

struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, int len);

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
int pico_transport_error(struct pico_frame *f, uint8_t proto, int code);

/* Socket loop */
int pico_sockets_loop(int loop_score);

/* Port check */
int pico_is_port_free(uint16_t proto, uint16_t port);


#endif
