#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_tcp.h"


static int assign_high_random_port(struct pico_socket *s)
{
  s->local_port = 0xFDFD;
  return 0;
}

static int socket_cmp(struct pico_socket *a, struct pico_socket *b)
{
  int a_is_ip6 = is_sock_ipv6(a);
  int b_is_ip6 = is_sock_ipv6(b);
  int proto_a = is_sock_tcp(a);
  int proto_b = is_sock_tcp(b);
  int a_is_connected = a->state & PICO_SOCKET_STATE_CONNECTED;
  int b_is_connected = b->state & PICO_SOCKET_STATE_CONNECTED;
  int diff;
  

  /* First: order by proto (UDP/TCP) */
  if (proto_a < proto_b)
    return -1;
  if (proto_a > proto_b)
    return 1;

  /* Then, order by network ver */
  if (a_is_ip6 < b_is_ip6)
    return -1;
  if (a_is_ip6 > b_is_ip6)
    return 1;

  /* Then, order by local port */
  if (a->local_port < b->local_port)
    return -1;
  if (a->local_port > b->local_port)
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

  /* And finally by port. The two sockets are coincident if the quad is the same. */
  return b->remote_port - a->remote_port;
}

RB_HEAD(socket_tree, pico_socket);
RB_PROTOTYPE_STATIC(socket_tree, pico_socket, node, socket_cmp);
RB_GENERATE_STATIC(socket_tree, pico_socket, node, socket_cmp);

struct socket_tree Socket_tree;

struct pico_socket *pico_socket_open(uint16_t net, uint16_t proto)
{
  struct pico_socket *s = pico_zalloc(sizeof(struct pico_socket));
  if (!s)
    goto fail;

  s->q_in = pico_zalloc(sizeof(struct pico_queue));
  if (!s->q_in)
    goto fail;

  s->q_out = pico_zalloc(sizeof(struct pico_queue));
  if (!s->q_out)
    goto fail;

#ifdef PICO_SUPPORT_IPV4
  if (net == 4)
    s->net = &pico_proto_ipv4;
#endif

#ifdef PICO_SUPPORT_IPV6
  if (net == 6)
    s->net = &pico_proto_ipv6;
#endif

#ifdef PICO_SUPPORT_TCP
  if (proto == PICO_PROTO_TCP)
    s->proto = &pico_proto_tcp;
#endif

#ifdef PICO_SUPPORT_UDP
  if (proto == PICO_PROTO_UDP)
    s->proto = &pico_proto_udp;
#endif

  if (!net || !proto)
    goto fail;

  return s;

fail:
  if (s->q_in)
    pico_free(s->q_in);
  if (s->q_out)
    pico_free(s->q_out);
  if (s)
    pico_free(s);
  return NULL;
}


int pico_socket_read(struct pico_socket *s, void *buf, int len)
{
  return 0;
}

int pico_socket_write(struct pico_socket *s, void *buf, int len)
{

  return 0;
}


int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port)
{

  return 0;
}

int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *local_port)
{

  return 0;
}


int pico_socket_bind(struct pico_socket *s, void *local_addr, uint16_t *port)
{
  if (!s || !local_addr || port)
    return -1;

  s->local_port = *port;

  if ((0 == s->local_port) && assign_high_random_port(s))
    return -1;

  *port = s->local_port; /* As return value. */

  if (is_sock_ipv6(s)) {
    struct pico_ip6 *ip = (struct pico_ip6 *) local_addr;
    memcpy(s->local_addr.ip6.addr, ip, PICO_SIZE_IP6);
  } else if (is_sock_ipv4(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *) local_addr;
    s->local_addr.ip4.addr = ip->addr;
  }
  s->state |= PICO_SOCKET_STATE_BOUND;
  RB_INSERT(socket_tree, &Socket_tree, s);
  return 0;
}

int pico_socket_connect(struct pico_socket *s, void *srv_addr, uint16_t remote_port)
{

  return 0;
}

int pico_socket_listen(struct pico_socket *s)
{

  return 0;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{

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


