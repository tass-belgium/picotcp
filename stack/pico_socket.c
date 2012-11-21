#include "pico_config.h"
#include "pico_queue.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_stack.h"

#define PROTO(s) ((s)->proto->proto_number)

#ifdef PICO_SUPPORT_IPV4
# define IS_SOCK_IPV4(s) ((s->net == &pico_proto_ipv4))
#else
# define IS_SOCK_IPV4(s) (0)
#endif

#ifdef PICO_SUPPORT_IPV6
# define IS_SOCK_IPV6(s) ((s->net == &pico_proto_ipv6))
#else
# define IS_SOCK_IPV6(s) (0)
#endif

struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, int len);

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


  /* If either socket is INADDR_ANY mode, skip local address comparison */

  /* At this point, sort by local host */

  if (0) {
#ifdef PICO_SUPPORT_IPV6
  } else if (a_is_ip6) {
    if ((memcmp(a->local_addr.ip6.addr, PICO_IP6_ANY, PICO_SIZE_IP6)==0) || memcmp((b->local_addr.ip6.addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0))
      diff = 0;
    else
      diff = memcmp(a->local_addr.ip6.addr, b->local_addr.ip6.addr, PICO_SIZE_IP6);
#endif
  } else {
    if ((a->local_addr.ip4.addr == PICO_IP4_ANY) || (b->local_addr.ip4.addr == PICO_IP4_ANY))
      diff = 0;
    else
      diff = a->local_addr.ip4.addr - b->local_addr.ip4.addr;
  }

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

int pico_socket_add(struct pico_socket *s)
{
  struct pico_sockport *sp = pico_get_sockport(PROTO(s), s->local_port);
  if (!sp) {
    dbg("Creating sockport..%04x\n", s->local_port);
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
  dbg("inserting...\n");
  RB_INSERT(socket_tree, &sp->socks, s);
  s->state |= PICO_SOCKET_STATE_BOUND;

  RB_FOREACH(s, socket_tree, &sp->socks) {
    dbg("List Socket lc=%hu rm=%hu\n", short_be(s->local_port), short_be(s->remote_port));
  }
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
  s->state &= (~PICO_SOCKET_STATE_BOUND);
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
  struct pico_trans *tr = (struct pico_trans *)f->transport_hdr;

  if (!tr)
    return -1;

  sp = pico_get_sockport(p->proto_number, localport);

  if (!sp)
    return -1;



#ifdef PICO_SUPPORT_TCP
  if (p->proto_number == PICO_PROTO_TCP) {
    RB_FOREACH(s, socket_tree, &sp->socks) {
      if ((s->remote_port == 0) || (s->remote_port == tr->sport)) {
        struct pico_frame *cpy = pico_frame_copy(f);
        pico_tcp_input(s, cpy);
        if (s->remote_port == tr->sport)
          break;
      }
    }
    pico_frame_discard(f);
    return 0;
  }
#endif

#ifdef PICO_SUPPORT_UDP
  if (p->proto_number == PICO_PROTO_UDP) {
    /* Take the only socket here. */
    s = RB_ROOT(&sp->socks);
  }
  if (!s)
    return -1;
  if (pico_enqueue(&s->q_in, f) > 0) {
    s->wakeup(PICO_SOCK_EV_RD, s);
    return 0;
  }
  else
#endif
  return -1;
}

struct pico_socket *pico_socket_open(uint16_t net, uint16_t proto, void (*wakeup)(uint16_t ev, struct pico_socket *))
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


struct pico_socket *pico_socket_clone(struct pico_socket *facsimile)
{

  struct pico_socket *s = NULL;

#ifdef PICO_SUPPORT_UDP
  if (facsimile->proto->proto_number == PICO_PROTO_UDP) {
    s = pico_udp_open();
    s->proto = &pico_proto_udp;
  }
#endif

#ifdef PICO_SUPPORT_TCP
  if (facsimile->proto->proto_number == PICO_PROTO_TCP) {
    s = pico_tcp_open();
    s->proto = &pico_proto_tcp;
  }
#endif

  if (!s)
    return NULL;
  s->local_port = facsimile->local_port;
  s->remote_port = facsimile->remote_port;
  s->state = facsimile->state;

#ifdef PICO_SUPPORT_IPV4
  if (facsimile->net == &pico_proto_ipv4) {
    s->net = &pico_proto_ipv4;
    memcpy(&s->local_addr, &facsimile->local_addr, sizeof(struct pico_ip4));
    memcpy(&s->remote_addr, &facsimile->remote_addr, sizeof(struct pico_ip4));
  }
#endif

#ifdef PICO_SUPPORT_IPV6
  if (net == &pico_proto_ipv6) {
    s->net = &pico_proto_ipv6;
    memcpy(&s->local_addr, &facsimile->local_addr, sizeof(struct pico_ip6));
    memcpy(&s->remote_addr, &facsimile->remote_addr, sizeof(struct pico_ip6));
  }
#endif
  s->q_in.max_size = PICO_DEFAULT_SOCKETQ;
  s->q_out.max_size = PICO_DEFAULT_SOCKETQ;
  s->wakeup = NULL;
  if (!s->net) {
    pico_free(s);
    return NULL;
  }
  return s;
}

int pico_socket_read(struct pico_socket *s, void *buf, int len)
{
  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP)
    return pico_udp_recv(s, buf, len, NULL, NULL);
#endif

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    return pico_tcp_read(s, buf, len);
#endif
  return 0;
}

int pico_socket_write(struct pico_socket *s, void *buf, int len)
{
  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0)
    return -1;
  return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
}


int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port)
{

  struct pico_frame *f;
  int off = 0;
  if (len <= 0)
    return len;
#ifdef PICO_SUPPORT_IPV4
  struct pico_ip4 *src4;
#endif

#ifdef PICO_SUPPORT_IPV6
  struct pico_ip6 *src6;
#endif

  if (!dst || !remote_port)
    return -1;

  if ((s->state & PICO_SOCKET_STATE_CONNECTED) != 0) {
    if (remote_port != s->remote_port)
      return -1;
  }

  if (len <= 0)
    return 0;

#ifdef PICO_SUPPORT_IPV4
  if (IS_SOCK_IPV4(s)) {
    if ((s->state & PICO_SOCKET_STATE_CONNECTED)) {
      if  (s->remote_addr.ip4.addr != ((struct pico_ip4 *)dst)->addr )
        return -1;
    } else {
      src4 = pico_ipv4_source_find(dst);
      if (!src4)
        return -1;
      s->local_addr.ip4.addr = src4->addr;
      s->remote_addr.ip4.addr = ((struct pico_ip4 *)dst)->addr;
    }
  }
#endif

#ifdef PICO_SUPPORT_IPV6
  if (IS_SOCK_IPV6(s)) {
    if (s->state & PICO_SOCKET_STATE_CONNECTED) {
      if (memcmp(&s->remote_addr, dst, PICO_SIZE_IP6))
        return -1;
    } else {
      src6 = pico_ipv6_source_find(dst);
      if (!src6)
        return -1;
      memcpy(&s->local_addr, src6, PICO_SIZE_IP6);
      memcpy(&s->remote_addr, dst, PICO_SIZE_IP6);
    }
  }
#endif

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    //s->local_port = pico_socket_high_port(s->proto->proto_number);
    s->local_port = short_be(60000);
  }
  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
    s->remote_port = remote_port;
  }


#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    off = pico_tcp_overhead(s);
#endif


  f = pico_socket_frame_alloc(s, off + len);
  if (!f)
    return -1;

  f->payload += off;
  f->payload_len -= off;
  f->sock = s;
  memcpy(f->payload, buf, f->payload_len);
  //dbg("Pushing segment, hdr len: %d, payload_len: %d\n", f->transport_len, f->payload_len);
  if (s->proto->push(s->proto, f) > 0) {
    return f->payload_len;
  } else {
    pico_frame_discard(f);
    return 0;
  }
}

int pico_socket_send(struct pico_socket *s, void *buf, int len)
{
  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0)
    return -1;
  return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
}

int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *remote_port)
{
  dbg("STATE: %x", s->state);
  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0)
    return -1;
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP) {
    return pico_udp_recv(s, buf, len, orig, remote_port);
  }
#endif
#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    return pico_tcp_read(s, buf, len);
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
  dbg("Socket is bound.\n");
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
  /* TODO: identify problems like destination socket unreachable, and return an error here. */
  return 0;
}

#ifdef PICO_SUPPORT_TCP

int pico_socket_listen(struct pico_socket *s, int backlog)
{
  if (PROTO(s) == PICO_PROTO_UDP)
    return -1;

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0)
    return -1;

  if (backlog < 1)
    return -1;

  if (PROTO(s) == PICO_PROTO_TCP)
    pico_socket_alter_state(s, PICO_SOCKET_STATE_TCP_SYN_SENT, 0, PICO_SOCKET_STATE_TCP_LISTEN);
  s->max_backlog = backlog;

  return 0;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{
  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0)
    return NULL;

  if (PROTO(s) == PICO_PROTO_UDP)
    return NULL;

  if (TCPSTATE(s) == PICO_SOCKET_STATE_TCP_LISTEN) {
    struct pico_sockport *sp = pico_get_sockport(PICO_PROTO_TCP, s->local_port);
    struct pico_socket *found;
    if (sp) {
      RB_FOREACH(found, socket_tree, &sp->socks) {
        if (s == found->parent) {
          found->parent = NULL;
          return found;
        }
      }
    }
  }
  return NULL;
}

#else

int pico_socket_listen(struct pico_socket *s)
{
  return -1;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{
  return NULL;
}

#endif


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
#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP) {
    if (mode & PICO_SHUT_RDWR)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_TCP_CLOSED, PICO_SOCKET_STATE_CLOSING |PICO_SOCKET_STATE_BOUND | PICO_SOCKET_STATE_CONNECTED, 0);
    else if (mode & PICO_SHUT_RD)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
  }
#endif
#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP) {

  }
#endif
  return 0;
}

int pico_socket_close(struct pico_socket *s)
{
  return pico_socket_shutdown(s, PICO_SHUT_RDWR);
}


int pico_transport_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_trans *hdr = (struct pico_trans *) f->transport_hdr;
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
#ifdef PICO_SUPPORT_TCP
  RB_FOREACH(sp, sockport_table, &TCPTable) {
    RB_FOREACH(s, socket_tree, &sp->socks) {
      loop_score = pico_tcp_output(s, loop_score);
      if (loop_score <= 0)
        return 0;
    }
  }
#endif

  return loop_score;
}

struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, int len)
{
  int overhead = 0;
  struct pico_frame *f = NULL;

#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP)
    overhead = sizeof(struct pico_udp_hdr);
#endif

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    overhead = 0; /* Overhead is calculated within TCP */
#endif


#ifdef PICO_SUPPORT_IPV6
  if (IS_SOCK_IPV6(s))
    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, overhead + len);
#endif

#ifdef PICO_SUPPORT_IPV4
  if (IS_SOCK_IPV4(s))
    f = pico_proto_ipv4.alloc(&pico_proto_ipv4, overhead + len);
#endif
  if (!f)
    return f;
  f->sock = s;
  f->payload = f->transport_hdr + overhead;
  f->payload_len = len;
  return f;
}

