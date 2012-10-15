#include "pico_queue.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_stack.h"

#define PROTO(s) ((s)->proto->proto_number)
#define TCPSTATE(s) ((s)->state & PICO_SOCKET_STATE_TCP)

static int socket_cmp(struct pico_socket *a, struct pico_socket *b)
{
  int a_is_ip6 = is_sock_ipv6(a);
  int b_is_ip6 = is_sock_ipv6(b);
  int a_is_connected = a->state & PICO_SOCKET_STATE_CONNECTED;
  int b_is_connected = b->state & PICO_SOCKET_STATE_CONNECTED;
  int diff;

  /* First, order by network ver */
  if (a_is_ip6 < b_is_ip6)
    return -1;
  if (a_is_ip6 > b_is_ip6)
    return 1;

  /* Unconnected sockets are equal at this point. */
  if ((a_is_connected == 0) && (b_is_connected == 0))
    return 0;

  /* if not both are connected, they are sorted. */
  if (!a_is_connected)
    return -1;
  if (!b_is_connected)
    return 1;

  /* At this point, sort by local host */
  if (a_is_ip6)
    diff = memcmp(a->local_addr.ip6.addr, b->local_addr.ip6.addr, PICO_SIZE_IP6);
  else
    diff = a->local_addr.ip4.addr - b->local_addr.ip4.addr;

  if (diff)
    return diff;


  /* Sort by remote host */
  if (a_is_ip6)
    diff = memcmp(a->remote_addr.ip6.addr, b->remote_addr.ip6.addr, PICO_SIZE_IP6);
  else
    diff = a->remote_addr.ip4.addr - b->remote_addr.ip4.addr;

  if (diff)
    return diff;

  /* And finally by remote port. The two sockets are coincident if the quad is the same. */
  return b->remote_port - a->remote_port;
}

RB_HEAD(socket_tree, pico_socket);
RB_PROTOTYPE_STATIC(socket_tree, pico_socket, node, socket_cmp);
RB_GENERATE_STATIC(socket_tree, pico_socket, node, socket_cmp);

struct pico_sockport
{
  struct socket_tree socks;
  uint16_t number;
  uint16_t proto;
  RB_ENTRY(pico_sockport) node;
};

int sockport_cmp(struct pico_sockport *a, struct pico_sockport *b)
{
  if (a->number < b->number)
    return -1;
  if (a->number > b->number)
    return 1;
  return 0;
}

RB_HEAD(sockport_table, pico_sockport);
RB_PROTOTYPE_STATIC(sockport_table, pico_sockport, node, sockport_cmp);
RB_GENERATE_STATIC(sockport_table, pico_sockport, node, sockport_cmp);

static struct sockport_table UDPTable;
static struct sockport_table TCPTable;

static struct pico_sockport *pico_get_sockport(uint16_t proto, uint16_t port)
{
  struct pico_sockport test;
  test.number = port;
  if (proto == PICO_PROTO_UDP)
    return RB_FIND(sockport_table, &UDPTable, &test);
  else if (proto == PICO_PROTO_TCP)
    return RB_FIND(sockport_table, &TCPTable, &test);
  else return NULL;
}

static int pico_socket_add(struct pico_socket *s)
{
  struct pico_sockport *sp = pico_get_sockport(PROTO(s), s->local_port);
  if (!sp) {
    sp = pico_zalloc(sizeof(struct pico_sockport));
      if (!sp)
        return -1;
    sp->proto = PROTO(s);
    sp->number = s->local_port;
    if (PROTO(s) == PICO_PROTO_UDP)
      RB_INSERT(sockport_table, &UDPTable, sp); 
    else if (PROTO(s) == PICO_PROTO_TCP)
      RB_INSERT(sockport_table, &TCPTable, sp);
  }
  RB_INSERT(socket_tree, &sp->socks, s);
  return 0;
}

static int pico_socket_del(struct pico_socket *s)
{
  struct pico_sockport *sp = pico_get_sockport(PROTO(s), s->local_port);
  if (!sp) {
    return -1;
  }
  RB_REMOVE(socket_tree, &sp->socks, s);

  /* Remove associated socketport, if empty */
  if (RB_EMPTY(&sp->socks)) {
    if (PROTO(s) == PICO_PROTO_UDP)
      RB_REMOVE(sockport_table, &UDPTable, sp);
    else if (PROTO(s) == PICO_PROTO_TCP)
      RB_REMOVE(sockport_table, &TCPTable, sp);
    pico_free(sp);
  }
  return 0;
}

static int pico_socket_alter_state(struct pico_socket *s, uint16_t more_states, uint16_t less_states, uint16_t tcp_state)
{
  struct pico_sockport *sp;
  if (more_states & PICO_SOCKET_STATE_BOUND)
    return pico_socket_add(s);

  if (less_states & PICO_SOCKET_STATE_BOUND)
    return pico_socket_del(s);

  sp = pico_get_sockport(PROTO(s), s->local_port);
  if (!sp)
    return -1;

  RB_REMOVE(socket_tree, &sp->socks, s);
  s->state |= more_states;
  s->state &= (~less_states);
  if (tcp_state) {
    s->state &= 0x00FF;
    s->state |= tcp_state;
  }
  RB_INSERT(socket_tree, &sp->socks, s);
  return 0;
}

static int pico_socket_deliver(struct pico_protocol *p, struct pico_frame *f, uint16_t localport)
{
  struct pico_sockport *sp;
  struct pico_socket *s;
  sp = pico_get_sockport(p->proto_number, localport);

  if (!sp)
    return -1;


#ifdef PICO_SUPPORT_UDP
  if (p->proto_number == PICO_PROTO_UDP) {
    /* Take the only socket here. */
    s = RB_ROOT(&sp->socks);
  }
#endif

#ifdef PICO_SUPPORT_TCP
  if (p->proto_number == PICO_PROTO_TCP) {
    /* XXX: Find the socket, call some tcp_rcv fn */
  }
#endif
  if (!s)
    return -1;
  if (pico_enqueue(&s->q_in, f) > 0) {
    s->wakeup(s);
    return 0;
  }
  else
    return -1;
}

struct pico_socket *pico_socket_open(uint16_t net, uint16_t proto, void (*wakeup)(struct pico_socket *))
{

  struct pico_socket *s = NULL;

#ifdef PICO_SUPPORT_UDP
  if (proto == PICO_PROTO_UDP) {
    s = pico_udp_open();
    s->proto = &pico_proto_udp;
  }
#endif

#ifdef PICO_SUPPORT_TCP
  if (proto == PICO_PROTO_TCP) {
    s = pico_tcp_open();
    s->proto = &pico_proto_tcp;
  }
#endif

  if (!s)
    return NULL;

#ifdef PICO_SUPPORT_IPV4
  if (net == PICO_PROTO_IPV4)
    s->net = &pico_proto_ipv4;
#endif

#ifdef PICO_SUPPORT_IPV6
  if (net == PICO_PROTO_IPV6)
    s->net = &pico_proto_ipv6;
#endif

  s->q_in.max_size = PICO_DEFAULT_SOCKETQ;
  s->q_out.max_size = PICO_DEFAULT_SOCKETQ;
  s->wakeup = wakeup;

  if (!s->net) {
    pico_free(s);
    return NULL;
  }
  return s;
}


int pico_socket_read(struct pico_socket *s, void *buf, int len)
{
  if ((s->state | PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP)
    return pico_udp_recv(s, buf, len, NULL, NULL);
#endif
  return 0;
}

int pico_socket_write(struct pico_socket *s, void *buf, int len)
{
  if ((s->state | PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
  if ((s->state | PICO_SOCKET_STATE_CONNECTED) == 0)
    return -1;

  return 0;
}


int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port)
{

  if (!dst || !remote_port)
    return -1;

#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP)
    return pico_udp_send(s, buf, len, dst, remote_port);
#endif
  return 0;
}

int pico_socket_send(struct pico_socket *s, void *buf, int len)
{
  if ((s->state | PICO_SOCKET_STATE_CONNECTED) == 0)
    return -1;

  return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
}

int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *remote_port)
{
  if ((s->state | PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP)
    return pico_udp_recv(s, buf, len, orig, remote_port);
#endif
  return 0;
}

int pico_socket_recv(struct pico_socket *s, void *buf, int len)
{
  return pico_socket_recvfrom(s, buf, len, NULL, NULL);
}


int pico_socket_bind(struct pico_socket *s, void *local_addr, uint16_t *port)
{
  if (!s || !local_addr || !port)
    return -1;

  s->local_port = *port;

  /* XXX verify  +  change if 0 */

  *port = s->local_port; /* As return value. */

  if (is_sock_ipv6(s)) {
    struct pico_ip6 *ip = (struct pico_ip6 *) local_addr;
    memcpy(s->local_addr.ip6.addr, ip, PICO_SIZE_IP6);
  } else if (is_sock_ipv4(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *) local_addr;
    s->local_addr.ip4.addr = ip->addr;
  }
  return pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
}

int pico_socket_connect(struct pico_socket *s, void *remote_addr, uint16_t remote_port)
{
  if (remote_port == 0)
    return -1;

  s->remote_port = remote_port;

  if (is_sock_ipv6(s)) {
    struct pico_ip6 *ip = (struct pico_ip6 *) remote_addr;
    memcpy(s->remote_addr.ip6.addr, ip, PICO_SIZE_IP6);
  } else if (is_sock_ipv4(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *) remote_addr;
    s->remote_addr.ip4.addr = ip->addr;
  }

#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP)
    pico_socket_alter_state(s, PICO_SOCKET_STATE_CONNECTED, 0, 0);
#endif

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    if (pico_tcp_initconn(s) == 0)
      pico_socket_alter_state(s, 0, 0, PICO_SOCKET_STATE_TCP_SYN_SENT);
#endif
  return 0;
}

int pico_socket_listen(struct pico_socket *s)
{
  if (PROTO(s) == PICO_PROTO_UDP)
    return -1;

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    pico_socket_alter_state(s, 0, 0, PICO_SOCKET_STATE_TCP_LISTEN);
#endif

  return 0;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{
  if ((s->state | PICO_SOCKET_STATE_BOUND) == 0)
    return NULL;

  if (PROTO(s) == PICO_PROTO_UDP)
    return NULL;

  return NULL;
}


int pico_socket_setoption(struct pico_socket *s, int option, void *value)
{

  return 0;
}

int pico_socket_getoption(struct pico_socket *s, int option, void *value)
{

  return 0;
}


int pico_socket_shutdown(struct pico_socket *s, int mode)
{

  return 0;
}

int pico_socket_close(struct pico_socket *s)
{

  return 0;
}


int pico_transport_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_trans *hdr = (struct pico_trans *) f->transport_hdr;
  dbg("Socket deliver\n");
  if ((hdr) && (pico_socket_deliver(self, f, hdr->dport) == 0))
    return 0;

  dbg("Socket not found... \n");
  pico_notify_socket_unreachable(f);
  pico_frame_discard(f);
  return -1;
}

int pico_sockets_loop(int loop_score)
{
  struct pico_sockport *sp;
  struct pico_socket *s;
  struct pico_frame *f;

#ifdef PICO_SUPPORT_UDP
  RB_FOREACH(sp, sockport_table, &UDPTable) {
    RB_FOREACH(s, socket_tree, &sp->socks) {
      f = pico_dequeue(&s->q_out);
      while (f && (loop_score > 0)) {
        pico_proto_udp.push(&pico_proto_udp, f);
        loop_score -= 1;
        f = pico_dequeue(&s->q_out);
      }
    }
  }
#endif
  return loop_score;
}
