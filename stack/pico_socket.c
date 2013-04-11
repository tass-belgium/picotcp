/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.


Authors: Daniele Lacamera
*********************************************************************/


#include "pico_config.h"
#include "pico_queue.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_stack.h"
#include "pico_icmp4.h"
#include "pico_nat.h"
#include "pico_tree.h"
#include "pico_device.h"

#if defined (PICO_SUPPORT_IPV4) || defined (PICO_SUPPORT_IPV6)
#if defined (PICO_SUPPORT_TCP) || defined (PICO_SUPPORT_UDP)


#define PROTO(s) ((s)->proto->proto_number)

#ifdef PICO_SUPPORT_TCP
# define IS_NAGLE_ENABLED(s) (s->opt_flags & (1 << PICO_SOCKET_OPT_TCPNODELAY))
#endif

#define PICO_SOCKET_MTU 1480 /* Ethernet MTU(1500) - IP header size(20) */

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

#ifdef PICO_SUPPORT_IPFRAG
# define frag_dbg(...) do{}while(0) 
#endif

static struct pico_sockport *sp_udp = NULL ,*sp_tcp = NULL;

struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, int len);

static int socket_cmp(void * ka, void * kb)
{
  struct pico_socket *a = ka, *b = kb;
  int a_is_ip6 = is_sock_ipv6(a);
  int b_is_ip6 = is_sock_ipv6(b);

  int diff;

  /* First, order by network ver */
  if (a_is_ip6 < b_is_ip6)
    return -1;
  if (a_is_ip6 > b_is_ip6)
    return 1;

  /* If either socket is PICO_IPV4_INADDR_ANY mode, skip local address comparison */

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

struct pico_sockport
{
  struct pico_tree socks; // how you make the connection ?
  uint16_t number;
  uint16_t proto;
};

#define INIT_SOCKPORT { {&LEAF , socket_cmp}, 0, 0 }

int sockport_cmp(void * ka, void * kb)
{
  struct pico_sockport *a = ka, *b = kb;
  if (a->number < b->number)
    return -1;
  if (a->number > b->number)
    return 1;
  return 0;
}

PICO_TREE_DECLARE(UDPTable,sockport_cmp);
PICO_TREE_DECLARE(TCPTable,sockport_cmp);

static struct pico_sockport *pico_get_sockport(uint16_t proto, uint16_t port)
{
  struct pico_sockport test = INIT_SOCKPORT;
  test.number = port;

  if (proto == PICO_PROTO_UDP)
    return pico_tree_findKey(&UDPTable,&test);

  else if (proto == PICO_PROTO_TCP)
    return pico_tree_findKey(&TCPTable,&test);

  else return NULL;
}

int pico_is_port_free(uint16_t proto, uint16_t port, void *addr, void *net)
{
  struct pico_sockport *sp;
  struct pico_ip4 *ip;
  sp = pico_get_sockport(proto, port);

  if (!net)
    net = &pico_proto_ipv4;


  /** IPv6 (wip) ***/
  if (net != &pico_proto_ipv4) {
    dbg("IPV6!!!!!\n");
    return (!sp);
  }

  /* IPv4 */
#ifdef PICO_SUPPORT_NAT
  if (pico_ipv4_nat_find(port,NULL, 0,proto) == 0) {
    dbg("In use by nat....\n");
    return 0;
  }
#endif
  ip = (struct pico_ip4 *)addr;
  if (ip->addr == PICO_IPV4_INADDR_ANY) {
    if (!sp) return 1;
      else {
        dbg("In use, and asked for ANY\n");
        return 0;
      }
  }
  if (sp) {
    struct pico_ip4 *s_local;
    struct pico_tree_node *idx;
    struct pico_socket *s;
    pico_tree_foreach(idx, &sp->socks) {
      s = idx->keyValue;
      if (s->net == &pico_proto_ipv4) {
        s_local = (struct pico_ip4*) &s->local_addr;
        if ((s_local->addr == PICO_IPV4_INADDR_ANY) || (s_local->addr == ip->addr))
          return 0;
      }
    }
  }
  return 1;
}

static int pico_check_socket(struct pico_socket *s)
{
  struct pico_sockport *test;
  struct pico_socket *found;
  struct pico_tree_node * index;

  test = pico_get_sockport(PROTO(s), s->local_port);
  
  if (!test) {
    return -1;
  }

  pico_tree_foreach(index,&test->socks){
    found = index->keyValue;
    if (s == found) {
      return 0;
    }
  }

  return -1;
}


int pico_socket_add(struct pico_socket *s)
{
  struct pico_sockport *sp = pico_get_sockport(PROTO(s), s->local_port);
  if (!sp) {
    //dbg("Creating sockport..%04x\n", s->local_port); /* In comment due to spam during test */
    sp = pico_zalloc(sizeof(struct pico_sockport));

    if (!sp) {
      pico_err = PICO_ERR_ENOMEM;
      return -1;
    }
    sp->proto = PROTO(s);
    sp->number = s->local_port;
    sp->socks.root = &LEAF;
    sp->socks.compare = socket_cmp;

    if (PROTO(s) == PICO_PROTO_UDP)
    {
      pico_tree_insert(&UDPTable,sp);
    }
    else if (PROTO(s) == PICO_PROTO_TCP)
    {
      pico_tree_insert(&TCPTable,sp);
    }
  }

  pico_tree_insert(&sp->socks,s);
  s->state |= PICO_SOCKET_STATE_BOUND;

#if DEBUG_SOCKET_TREE
  {
    struct pico_tree_node * index;
    //RB_FOREACH(s, socket_tree, &sp->socks) {
    pico_tree_foreach(index,&sp->socks){
      s = index->keyValue;
      dbg(">>>> List Socket lc=%hu rm=%hu\n", short_be(s->local_port), short_be(s->remote_port));
    }

  }
#endif
  return 0;
}

static void socket_garbage_collect(unsigned long now, void *arg)
{
  struct pico_socket *s = (struct pico_socket *) arg;
  pico_free(s);
}

int pico_socket_del(struct pico_socket *s)
{
  struct pico_sockport *sp = pico_get_sockport(PROTO(s), s->local_port);

  if (!sp) {
    pico_err = PICO_ERR_ENXIO;
    return -1;
  }
  pico_tree_delete(&sp->socks,s);

  if(pico_tree_empty(&sp->socks)){
    if (PROTO(s) == PICO_PROTO_UDP)
    {
      pico_tree_delete(&UDPTable,sp);
    }
    else if (PROTO(s) == PICO_PROTO_TCP)
    {
      pico_tree_delete(&TCPTable,sp);
    }

    if(sp_tcp == sp)  sp_tcp = NULL;

    if(sp_udp == sp)   sp_udp = NULL;

    pico_free(sp);

  }

  s->state = PICO_SOCKET_STATE_CLOSED;
  pico_timer_add(3000, socket_garbage_collect, s);


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
  if (!sp) {
    pico_err = PICO_ERR_ENXIO;
    return -1;
  }

  pico_tree_delete(&sp->socks,s);

  s->state |= more_states;
  s->state &= (~less_states);
  if (tcp_state) {
    s->state &= 0x00FF;
    s->state |= tcp_state;
  }

  pico_tree_insert(&sp->socks,s);

  return 0;
}

static int pico_socket_deliver(struct pico_protocol *p, struct pico_frame *f, uint16_t localport)
{
  struct pico_frame *cpy = NULL;
  struct pico_sockport *sp = NULL;
  struct pico_socket *s = NULL, *found = NULL;
  struct pico_trans *tr = (struct pico_trans *)f->transport_hdr;
  struct pico_tree_node *index = NULL;
  #ifdef PICO_SUPPORT_IPV4
  struct pico_ipv4_hdr *ip4hdr;
  #endif
  #ifdef PICO_SUPPORT_IPV6
  struct pico_ipv6_hdr *ip6hdr;
  #endif


  if (!tr)
    return -1;

  sp = pico_get_sockport(p->proto_number, localport);

  if (!sp)
    return -1;

  #ifdef PICO_SUPPORT_TCP
  if (p->proto_number == PICO_PROTO_TCP) {
    pico_tree_foreach(index,&sp->socks){
      s = index->keyValue;
      /* 4-tuple identification of socket (port-IP) */
      #ifdef PICO_SUPPORT_IPV4
      if (IS_IPV4(f)) {
        struct pico_ip4 *s_local, *s_remote, p_src, p_dst;
        ip4hdr = (struct pico_ipv4_hdr*)(f->net_hdr);
        s_local = (struct pico_ip4*) &s->local_addr.ip4;
        s_remote = (struct pico_ip4*) &s->remote_addr.ip4;
        p_src.addr = ip4hdr->src.addr;
        p_dst.addr = ip4hdr->dst.addr;
        if (  (s->remote_port == tr->sport) && /* local port check */
              (s_remote->addr == p_src.addr) && /* remote addr check */ 
              ((s_local->addr == PICO_IPV4_INADDR_ANY) || (s_local->addr == p_dst.addr))) { /* Either local socket is ANY, or matches dst */
          found = s;
          break;
        } else if ( (s->remote_port == 0)  && /* not connected... listening */
         ((s_local->addr == PICO_IPV4_INADDR_ANY) || (s_local->addr == p_dst.addr))) { /* Either local socket is ANY, or matches dst */
          /* listen socket */
          found = s;
        }
      }
      #endif
      #ifdef PICO_SUPPORT_IPV6    /* XXX TODO make compare for ipv6 addresses */
      if (IS_IPV6(f)) {
        ip6hdr = (struct pico_ipv6_hdr*)(f->net_hdr);
        if ( (s->remote_port == tr->sport) ) { // && (((struct pico_ip6) s->remote_addr.ip6).addr == ((struct pico_ip6)(ip6hdr->src)).addr) ) {
          found = s;
          break;
        } else if (s->remote_port == 0) {
          /* listen socket */
          found = s;
        }
      }
      #endif 
      if (found != NULL) {
        pico_tcp_input(found,f);
        if ((found->ev_pending) && found->wakeup) {
          found->wakeup(found->ev_pending, found);
        }
        return 0;
      } else {
        pico_frame_discard(f);
        dbg("SOCKET> mmm something wrong (prob sockport)\n");
        return -1;
      }
    } /* FOREACH */
  } /* TCP CASE */
#endif

#ifdef PICO_SUPPORT_UDP
  if (p->proto_number == PICO_PROTO_UDP) {
    pico_tree_foreach(index, &sp->socks) {
      s = index->keyValue;
      if (IS_IPV4(f)) { /* IPV4 */
        struct pico_ip4 s_local, p_dst, p_src;
        ip4hdr = (struct pico_ipv4_hdr*)(f->net_hdr);
        s_local.addr = s->local_addr.ip4.addr;
        p_dst.addr = ip4hdr->dst.addr;
        p_src.addr = ip4hdr->src.addr;
        if ((pico_ipv4_is_broadcast(p_dst.addr))) {
          struct pico_device *dev = pico_ipv4_link_find(&s->local_addr.ip4);
          if ((s_local.addr == PICO_IPV4_INADDR_ANY) || /* If our local ip is ANY, or.. */
            (dev == f->dev) ) { /* the source of the bcast packet is a neighbor... */
            cpy = pico_frame_copy(f);
            if (!cpy)
              return -1;
            if (pico_enqueue(&s->q_in, cpy) > 0) {
              if (s->wakeup)
                s->wakeup(PICO_SOCK_EV_RD, s);
            }
          }
        } else if ((s_local.addr == PICO_IPV4_INADDR_ANY) || (s_local.addr == p_dst.addr))
        { /* Either local socket is ANY, or matches dst */
          cpy = pico_frame_copy(f);
          if (!cpy)
            return -1;
          if (pico_enqueue(&s->q_in, cpy) > 0) {
            if (s->wakeup)
              s->wakeup(PICO_SOCK_EV_RD, s);
          }
        }
      } else {
        /*... IPv6 */
      }
    } /* FOREACH */
    pico_frame_discard(f);
    if (s)
      return 0;
    else
      return -1;
  }
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
    /*check if Nagle enabled */
    if (!IS_NAGLE_ENABLED(s))
      dbg("ERROR Nagle should be enabled here\n\n");
  }
#endif

  if (!s) {
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return NULL;
  }

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
    pico_err = PICO_ERR_ENETUNREACH;
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

  if (!s) {
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return NULL;
  }
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
    pico_err = PICO_ERR_ENETUNREACH;
    return NULL;
  }
  return s;
}

int pico_socket_read(struct pico_socket *s, void *buf, int len)
{
  if (!s || buf == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    /* See task #178 */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    pico_err = PICO_ERR_EIO;
    return -1;
  }
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP)
    return pico_udp_recv(s, buf, len, NULL, NULL);
#endif

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP){
    /* check if in shutdown state and if no more data in tcpq_in */
    if ((s->state & PICO_SOCKET_STATE_SHUT_REMOTE) && pico_tcp_queue_in_is_empty(s) ) {  
      pico_err = PICO_ERR_ESHUTDOWN;
      return -1;
    } else {
      return pico_tcp_read(s, buf, len);
    }
  }
#endif
  return 0;
}

int pico_socket_write(struct pico_socket *s, void *buf, int len)
{
  if (!s || buf == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    /* See task #178 */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    pico_err = PICO_ERR_EIO;
    return -1;
  }
  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
    pico_err = PICO_ERR_ENOTCONN;
    return -1;
  } else if (s->state & PICO_SOCKET_STATE_SHUT_LOCAL) {  /* check if in shutdown state */
    pico_err = PICO_ERR_ESHUTDOWN;
    return -1;
  } else {
    return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
  }
}

uint16_t pico_socket_high_port(uint16_t proto)
{
  uint16_t port;
  if (0 || 
#ifdef PICO_SUPPORT_TCP
  (proto == PICO_PROTO_TCP) ||
#endif
#ifdef PICO_SUPPORT_TCP
  (proto == PICO_PROTO_UDP) ||
#endif
  0) {
    do {
      uint32_t rand = pico_rand();
      port = (uint16_t) (rand & 0xFFFFU);
      port = (uint16_t)(port % (65535 - 1024)) + 1024U; 
      if (pico_is_port_free(proto, port, NULL, NULL)) {
        return short_be(port);
      }
    } while(1);
  }
  else return 0U;
}


int pico_socket_sendto(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port)
{
  struct pico_frame *f;
  struct pico_remote_duple *remote_duple = NULL;
  int header_offset = 0;
  int total_payload_written = 0;
#ifdef PICO_SUPPORT_IPV4
  struct pico_ip4 *src4;
#endif

#ifdef PICO_SUPPORT_IPV6
  struct pico_ip6 *src6;
#endif
  if (len == 0) {
    return 0;
  } else if (len < 0) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if (buf == NULL || s == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if (!dst || !remote_port) {
    pico_err = PICO_ERR_EADDRNOTAVAIL;
    return -1;
  }

  if ((s->state & PICO_SOCKET_STATE_CONNECTED) != 0) {
    if (remote_port != s->remote_port) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

#ifdef PICO_SUPPORT_IPV4
  if (IS_SOCK_IPV4(s)) {
    if ((s->state & PICO_SOCKET_STATE_CONNECTED)) {
      if  (s->remote_addr.ip4.addr != ((struct pico_ip4 *)dst)->addr ) {
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
      }
    } else {
    	if( ((struct pico_ip4 *)dst)->addr != PICO_IP4_BCAST)
    	{
				src4 = pico_ipv4_source_find(dst);
				if (!src4) {
					pico_err = PICO_ERR_EHOSTUNREACH;
					return -1;
				}
				s->local_addr.ip4.addr = src4->addr;
				s->remote_addr.ip4.addr = ((struct pico_ip4 *)dst)->addr;
    	}
#     ifdef PICO_SUPPORT_UDP
    	else if(PROTO(s) == PICO_PROTO_UDP)
    	{
    		// next function will check the bcast this way
    		s->local_addr.ip4.addr = PICO_IP4_BCAST;
    		s->remote_addr.ip4.addr = PICO_IP4_BCAST;
    	}

      /* socket remote info could change in a consecutive call, make persistent */
      if (PROTO(s) == PICO_PROTO_UDP) {
        remote_duple = pico_zalloc(sizeof(struct pico_remote_duple));
        remote_duple->remote_addr.ip4.addr = ((struct pico_ip4 *)dst)->addr;
        remote_duple->remote_port = remote_port;
      }
#     endif
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
      if (!src6) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return -1;
      }
      memcpy(&s->local_addr, src6, PICO_SIZE_IP6);
      memcpy(&s->remote_addr, dst, PICO_SIZE_IP6);
#     ifdef PICO_SUPPORT_UDP
      if (PROTO(s) == PICO_PROTO_UDP) {
        remote_duple = pico_zalloc(sizeof(struct pico_remote_duple));
        remote_duple->remote_addr.ip6.addr = ((struct pico_ip6 *)dst)->addr;
        remote_duple->remote_port = remote_port;
      }
#     endif
    }
  }
#endif

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    s->local_port = pico_socket_high_port(s->proto->proto_number);
    if (s->local_port == 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }
  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
    s->remote_port = remote_port;
  }

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP)
    header_offset = pico_tcp_overhead(s);
#endif

#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP)
    header_offset = sizeof(struct pico_udp_hdr);
#endif

  while (total_payload_written < len) {
    int transport_len = (len - total_payload_written) + header_offset; 
    if (transport_len > PICO_SOCKET_MTU)
      transport_len = PICO_SOCKET_MTU;
#ifdef PICO_SUPPORT_IPFRAG
    else {
      if (total_payload_written)
        transport_len -= header_offset; /* last fragment, do not allocate memory for transport header */
    }
#endif /* PICO_SUPPORT_IPFRAG */

    f = pico_socket_frame_alloc(s, transport_len);
    if (!f) {
      pico_err = PICO_ERR_ENOMEM;
      return -1;
    }
    f->payload += header_offset;
    f->payload_len -= header_offset;
    f->sock = s;
    if (remote_duple) {
      f->info = pico_zalloc(sizeof(struct pico_remote_duple));
      memcpy(f->info, remote_duple, sizeof(struct pico_remote_duple));
    }

#ifdef PICO_SUPPORT_IPFRAG
#  ifdef PICO_SUPPORT_UDP
    if (PROTO(s) == PICO_PROTO_UDP && ((len + header_offset) > PICO_SOCKET_MTU)) {
      /* hacking way to identify fragmentation frames: payload != transport_hdr -> first frame */
      if (!total_payload_written) {
        frag_dbg("FRAG: first fragmented frame %p | len = %u offset = 0\n", f, f->payload_len);
        /* transport header length field contains total length + header length */
        f->transport_len = len + header_offset;
        f->frag = short_be(PICO_IPV4_MOREFRAG); 
      } else {
        /* no transport header in fragmented IP */
        f->payload = f->transport_hdr;
        f->payload_len += header_offset;
        /* set offset in octets */
        f->frag = short_be((total_payload_written + header_offset) / 8); 
        if (total_payload_written + f->payload_len < len) {
          frag_dbg("FRAG: intermediate fragmented frame %p | len = %u offset = %u\n", f, f->payload_len, short_be(f->frag));
          f->frag |= short_be(PICO_IPV4_MOREFRAG);
        } else {
          frag_dbg("FRAG: last fragmented frame %p | len = %u offset = %u\n", f, f->payload_len, short_be(f->frag));
          f->frag &= short_be(PICO_IPV4_FRAG_MASK);
        }
      }
    } else {
      f->frag = short_be(PICO_IPV4_DONTFRAG);
    }
#  endif /* PICO_SUPPORT_UDP */
#endif /* PICO_SUPPORT_IPFRAG */

    if (f->payload_len <= 0) {
      pico_frame_discard(f);
      pico_free(remote_duple);
      return total_payload_written;
    }

    memcpy(f->payload, buf + total_payload_written, f->payload_len);
    //dbg("Pushing segment, hdr len: %d, payload_len: %d\n", header_offset, f->payload_len);

    if (s->proto->push(s->proto, f) > 0) {
      total_payload_written += f->payload_len;
    } else {
      pico_frame_discard(f);
      pico_err = PICO_ERR_EAGAIN;
      break;
    }
  }
  pico_free(remote_duple);
  return total_payload_written;
}

int pico_socket_send(struct pico_socket *s, void *buf, int len)
{
  if (!s || buf == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    /* See task #178 */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

  if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
    pico_err = PICO_ERR_ENOTCONN;
    return -1;
  }
  return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
}

int pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *remote_port)
{
  if (!s || buf == NULL) { /// || orig == NULL || remote_port == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
    /* See task #178 */
      return -1;
    }
  }

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    pico_err = PICO_ERR_EADDRNOTAVAIL;
    return -1;
  }
#ifdef PICO_SUPPORT_UDP 
  if (PROTO(s) == PICO_PROTO_UDP) {
    return pico_udp_recv(s, buf, len, orig, remote_port);
  }
#endif
#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP) {
    /* check if in shutdown state and if tcpq_in empty */
    if ((s->state & PICO_SOCKET_STATE_SHUT_REMOTE) && pico_tcp_queue_in_is_empty(s)) {
      pico_err = PICO_ERR_ESHUTDOWN;
      return -1;
    } else {
      //dbg("socket tcp recv\n");
      return pico_tcp_read(s, buf, len);
    }
  }
#endif
  //dbg("socket return 0\n");
  return 0;
}

int pico_socket_recv(struct pico_socket *s, void *buf, int len)
{
  return pico_socket_recvfrom(s, buf, len, NULL, NULL);
}


int pico_socket_bind(struct pico_socket *s, void *local_addr, uint16_t *port)
{
  if (!s || !local_addr || !port) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if (!is_sock_ipv6(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *)local_addr;
    if (ip->addr != PICO_IPV4_INADDR_ANY) {
      if (!pico_ipv4_link_find(local_addr)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
      }
    }
  } else {
    /*... IPv6 */
  }


  /* When given port = 0, get a random high port to bind to. */
  if (*port == 0) {
    *port = pico_socket_high_port(PROTO(s));
    if (*port == 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

  if (pico_is_port_free(PROTO(s), *port, &local_addr, s->net) == 0) {
    pico_err = PICO_ERR_EADDRINUSE;
    return -1;
  }
  s->local_port = *port;

  if (is_sock_ipv6(s)) {
    struct pico_ip6 *ip = (struct pico_ip6 *) local_addr;
    memcpy(s->local_addr.ip6.addr, ip, PICO_SIZE_IP6);
    /* XXX: port ipv4 functionality to ipv6 */
    /* Check for port already in use */
    if (pico_is_port_free(PROTO(s), *port, &local_addr, s->net)) {
      pico_err = PICO_ERR_EADDRINUSE;
      return -1;
    }
  } else if (is_sock_ipv4(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *) local_addr;
    s->local_addr.ip4.addr = ip->addr;
  }
  return pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
}

int pico_socket_connect(struct pico_socket *s, void *remote_addr, uint16_t remote_port)
{
  int ret = -1;
  pico_err = PICO_ERR_EPROTONOSUPPORT;
  if (!s || remote_addr == NULL || remote_port == 0) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  s->remote_port = remote_port;

  if (s->local_port == 0) {
    s->local_port = pico_socket_high_port(PROTO(s));
    if (!s->local_port) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
    pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
  }


  if (is_sock_ipv6(s)) {
    struct pico_ip6 *ip = (struct pico_ip6 *) remote_addr;
    memcpy(s->remote_addr.ip6.addr, ip, PICO_SIZE_IP6);
  } else if (is_sock_ipv4(s)) {
    struct pico_ip4 *ip = (struct pico_ip4 *) remote_addr;
    s->remote_addr.ip4.addr = ip->addr;
  }

#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP) {
    pico_socket_alter_state(s, PICO_SOCKET_STATE_CONNECTED, 0, 0);
    pico_err = PICO_ERR_NOERR;
    ret = 0;
  }
#endif

#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP) {
    if (pico_tcp_initconn(s) == 0) {
      pico_socket_alter_state(s, PICO_SOCKET_STATE_CONNECTED | PICO_SOCKET_STATE_TCP_SYN_SENT, 0, 0);
      pico_err = PICO_ERR_NOERR;
      ret = 0;
    } else {
      pico_err = PICO_ERR_EHOSTUNREACH;
    }
  }
#endif
  return ret;
}

#ifdef PICO_SUPPORT_TCP

int pico_socket_listen(struct pico_socket *s, int backlog)
{
  if (!s || backlog < 1) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    /* See task #178 */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

  if (PROTO(s) == PICO_PROTO_UDP) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    pico_err = PICO_ERR_EISCONN;
    return -1;
  }

  if (backlog < 1) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if (PROTO(s) == PICO_PROTO_TCP)
    pico_socket_alter_state(s, PICO_SOCKET_STATE_TCP_SYN_SENT, 0, PICO_SOCKET_STATE_TCP_LISTEN);
  s->max_backlog = backlog;

  return 0;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *port)
{
  if (!s || !orig || !port) {
    pico_err = PICO_ERR_EINVAL;
    return NULL;
  }

  pico_err = PICO_ERR_EINVAL;

  if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
    return NULL;
  }

  if (PROTO(s) == PICO_PROTO_UDP) {
    return NULL;
  }

  if (TCPSTATE(s) == PICO_SOCKET_STATE_TCP_LISTEN) {
    struct pico_sockport *sp = pico_get_sockport(PICO_PROTO_TCP, s->local_port);
    struct pico_socket *found;
    /* If at this point no incoming connection socket is found,
     * the accept call is valid, but no connection is established yet.
     */
    pico_err = PICO_ERR_EAGAIN; 
    if (sp) {
      struct pico_tree_node * index;
      //RB_FOREACH(found, socket_tree, &sp->socks) {
      pico_tree_foreach(index,&sp->socks){
        found = index->keyValue;
        if (s == found->parent) {
          found->parent = NULL;
          pico_err = PICO_ERR_NOERR;
          memcpy(orig, &found->remote_addr, sizeof(struct pico_ip4));
          *port = found->remote_port;
          return found;
        }
      }
    }
  }
  return NULL;
}

#else

int pico_socket_listen(struct pico_socket *s, int backlog)
{
  pico_err = PICO_ERR_EINVAL;
  return -1;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{
  pico_err = PICO_ERR_EINVAL;
  return NULL;
}

#endif

#define PICO_SOCKET_SETOPT_EN(socket,index)  (socket->opt_flags |=  (1 << index))
#define PICO_SOCKET_SETOPT_DIS(socket,index) (socket->opt_flags &= ~(1 << index))

int pico_socket_setoption(struct pico_socket *s, int option, void *value) // XXX no check against proto (vs setsockopt) or implicit by socket?
{
  if (s == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  pico_err = PICO_ERR_NOERR;

  switch (option)
  {
#ifdef PICO_SUPPORT_TCP
    case PICO_TCP_NODELAY:
          if (s->proto->proto_number == PICO_PROTO_TCP) {
            /* disable Nagle's algorithm */
            PICO_SOCKET_SETOPT_DIS(s,PICO_SOCKET_OPT_TCPNODELAY);
          } else {
            pico_err = PICO_ERR_EINVAL;
          }
          break;
#endif


#ifdef PICO_SUPPORT_MCAST
    case PICO_IP_MULTICAST_IF:
          pico_err = PICO_ERR_EOPNOTSUPP;
          return -1;
          break;

    case PICO_IP_MULTICAST_TTL:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            return pico_udp_set_mc_ttl(s, *((uint8_t *) value));
          }
          break;

    case PICO_IP_MULTICAST_LOOP:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            switch (*(uint8_t *) value)
            {
              case 0:
                /* do not loop back multicast datagram */
                PICO_SOCKET_SETOPT_DIS(s,PICO_SOCKET_OPT_MULTICAST_LOOP);
                break;

              case 1:
                /* do loop back multicast datagram */
                PICO_SOCKET_SETOPT_EN(s,PICO_SOCKET_OPT_MULTICAST_LOOP);
                break;  

              default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
             }
          }
          break;

    case PICO_IP_ADD_MEMBERSHIP:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            struct pico_ip_mreq *mreq = (struct pico_ip_mreq *) value;
            struct pico_ipv4_link *mcast_link;
            if (!mreq->mcast_link_addr.addr) {
              mcast_link = NULL; /* use default multicast link */
            } else {
              mcast_link = pico_ipv4_link_get(&mreq->mcast_link_addr);
              if (!mcast_link) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
              }
            }
            return pico_ipv4_mcast_join_group(&mreq->mcast_group_addr, mcast_link);
          }          
          break;

    case PICO_IP_DROP_MEMBERSHIP:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            struct pico_ip_mreq *mreq = (struct pico_ip_mreq *) value;
            struct pico_ipv4_link *mcast_link;
            if (!mreq->mcast_link_addr.addr) {
              mcast_link = NULL; /* use default multicast link */
            } else {
              mcast_link = pico_ipv4_link_get(&mreq->mcast_link_addr);
              if (!mcast_link) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
              }
            }
            return pico_ipv4_mcast_leave_group(&mreq->mcast_group_addr, mcast_link);
          }          
          break;
#endif /* PICO_SUPPORT_MCAST */

    default:
          pico_err = PICO_ERR_EINVAL;
          return -1;
  }

  if (pico_err != PICO_ERR_NOERR)
    return -1;
  else
    return 0;
}

#define PICO_SOCKET_GETOPT(socket,index) ((socket->opt_flags & (1 << index)) != 0)

int pico_socket_getoption(struct pico_socket *s, int option, void *value)
{  
  if (!s || !value) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  switch (option)
  {
#ifdef PICO_SUPPORT_TCP
    case PICO_TCP_NODELAY:
          if (s->proto->proto_number == PICO_PROTO_TCP)
            /* state Nagle's algorithm */
            *(int *)value = PICO_SOCKET_GETOPT(s,PICO_SOCKET_OPT_TCPNODELAY);
          else
            *(int *)value = 0;
          break;
#endif

#ifdef PICO_SUPPORT_MCAST
    case PICO_IP_MULTICAST_IF:
          pico_err = PICO_ERR_EOPNOTSUPP;
          return -1;
          break;

    case PICO_IP_MULTICAST_TTL:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            pico_udp_get_mc_ttl(s, (uint8_t *) value);
          } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
          }            
          break;

    case PICO_IP_MULTICAST_LOOP:
          if (s->proto->proto_number == PICO_PROTO_UDP) {
            *(uint8_t *)value = PICO_SOCKET_GETOPT(s,PICO_SOCKET_OPT_MULTICAST_LOOP);
          } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
          }
          break;
#endif /* PICO_SUPPORT_MCAST */

    default:
          pico_err = PICO_ERR_EINVAL;
          return -1;
  }

  return 0;
}


int pico_socket_shutdown(struct pico_socket *s, int mode)
{
  if (!s) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  } else {
    /* check if exists in tree */
    /* See task #178 */
    if (pico_check_socket(s) != 0) {
      pico_err = PICO_ERR_EINVAL;
      return -1;
    }
  }

#ifdef PICO_SUPPORT_UDP
  if (PROTO(s) == PICO_PROTO_UDP) {
    if (mode & PICO_SHUT_RDWR)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_CLOSED, PICO_SOCKET_STATE_CLOSING |PICO_SOCKET_STATE_BOUND | PICO_SOCKET_STATE_CONNECTED, 0);
    else if (mode & PICO_SHUT_RD)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
  }
#endif
#ifdef PICO_SUPPORT_TCP
  if (PROTO(s) == PICO_PROTO_TCP) {
    if (mode & PICO_SHUT_WR)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_LOCAL, 0, 0);
    else if (mode & PICO_SHUT_RD)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_REMOTE, 0, 0);
    else if (mode & PICO_SHUT_RDWR)
      pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_LOCAL | PICO_SOCKET_STATE_SHUT_REMOTE, 0, 0);
  }
#endif
  return 0;
}

int pico_socket_close(struct pico_socket *s)
{
  return pico_socket_shutdown(s, PICO_SHUT_RDWR);
}

#ifdef PICO_SUPPORT_CRC
static inline int pico_transport_crc_check(struct pico_frame *f)
{
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_udp_hdr *udp_hdr = NULL;
  uint16_t checksum_invalid = 1;

  switch (net_hdr->proto)
  {
    case PICO_PROTO_TCP:
      checksum_invalid = short_be(pico_tcp_checksum_ipv4(f));
      //dbg("TCP CRC validation == %u\n", checksum_invalid);
      if (checksum_invalid) {
        //dbg("TCP CRC: validation failed!\n");
        pico_frame_discard(f);
        return 0;
      }
      break;

    case PICO_PROTO_UDP:
      udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      if (short_be(udp_hdr->crc)) {
        checksum_invalid = short_be(pico_udp_checksum_ipv4(f));
        //dbg("UDP CRC validation == %u\n", checksum_invalid);
        if (checksum_invalid) {
          //dbg("UDP CRC: validation failed!\n");
          pico_frame_discard(f);
          return 0;
        }
      }
      break;

    default:
      // Do nothing
      break;
  }
  return 1;
}
#else
static inline int pico_transport_crc_check(struct pico_frame *f)
{
  return 1;
}
#endif /* PICO_SUPPORT_CRC */

int pico_transport_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_trans *hdr = (struct pico_trans *) f->transport_hdr;
  int ret = 0;

  if (!hdr) {
    pico_err = PICO_ERR_EFAULT;
    return -1;
  }

  ret = pico_transport_crc_check(f);
  if (ret < 1)
    return ret;
  else
    ret = 0;

  if ((hdr) && (pico_socket_deliver(self, f, hdr->dport) == 0))
    return ret;

  if (!IS_BCAST(f)) {
    dbg("Socket not found... \n");
    pico_notify_socket_unreachable(f);
#ifdef PICO_SUPPORT_TCP
    /* if tcp protocol send RST segment */
    //if (self->proto_number == PICO_PROTO_TCP)
    //  pico_tcp_reply_rst(f);
#endif
    ret = -1;
    pico_err = PICO_ERR_ENOENT;
  }
  pico_frame_discard(f);
  return ret;
}

#define SL_LOOP_MIN 1


int pico_sockets_loop(int loop_score)
{
  static struct pico_tree_node *index_udp, * index_tcp;

  struct pico_sockport *start;
  struct pico_socket *s;

#ifdef PICO_SUPPORT_UDP
  struct pico_frame *f;

  if (sp_udp == NULL)
  {
    index_udp = pico_tree_firstNode(UDPTable.root);
    sp_udp = index_udp->keyValue;
  }

  /* init start node */
  start = sp_udp;

  /* round-robin all transport protocols, break if traversed all protocols */
  while (loop_score > SL_LOOP_MIN && sp_udp != NULL) {
    struct pico_tree_node * index;

    pico_tree_foreach(index,&sp_udp->socks){
      s = index->keyValue;
      f = pico_dequeue(&s->q_out);
      while (f && (loop_score > 0)) {
        pico_proto_udp.push(&pico_proto_udp, f);
        loop_score -= 1;
        f = pico_dequeue(&s->q_out);
      }
    }

    index_udp = pico_tree_next(index_udp);
    sp_udp = index_udp->keyValue;

    if (sp_udp == NULL)
    {
      index_udp = pico_tree_firstNode(UDPTable.root);
      sp_udp = index_udp->keyValue;
    }
    if (sp_udp == start)
      break;
  }
#endif

#ifdef PICO_SUPPORT_TCP
  if (sp_tcp == NULL)
  {
    index_tcp = pico_tree_firstNode(TCPTable.root);
    sp_tcp = index_tcp->keyValue;
  }

  /* init start node */
  start = sp_tcp;

  while (loop_score > SL_LOOP_MIN && sp_tcp != NULL) {
    struct pico_tree_node * index;
    pico_tree_foreach(index, &sp_tcp->socks){
      s = index->keyValue;
      loop_score = pico_tcp_output(s, loop_score);
      if ((s->ev_pending) && s->wakeup) {
        s->wakeup(s->ev_pending, s);
      }
      if (loop_score <= 0) {
        loop_score = 0;
        break;
      }
    }

    /* check if RB_FOREACH ended, if not, break to keep the cur sp_tcp */
    if (s != NULL)
      break;

    index_tcp = pico_tree_next(index_tcp);
    sp_tcp = index_tcp->keyValue;

    if (sp_tcp == NULL)
    {
      index_tcp = pico_tree_firstNode(TCPTable.root);
      sp_tcp = index_tcp->keyValue;
    }
    if (sp_tcp == start)
      break;
  }
#endif

  return loop_score;
}


struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, int len)
{
  struct pico_frame *f = NULL;

#ifdef PICO_SUPPORT_IPV6
  if (IS_SOCK_IPV6(s))
    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, len);
#endif

#ifdef PICO_SUPPORT_IPV4
  if (IS_SOCK_IPV4(s))
    f = pico_proto_ipv4.alloc(&pico_proto_ipv4, len);
#endif
  if (!f) {
    pico_err = PICO_ERR_ENOMEM;
    return f;
  }
  f->payload = f->transport_hdr;
  f->payload_len = len;
  f->sock = s;
  return f;
}

int pico_transport_error(struct pico_frame *f, uint8_t proto, int code)
{
  int ret = -1;
  struct pico_trans *trans = (struct pico_trans*) f->transport_hdr;
  struct pico_sockport *port = NULL;
  struct pico_socket *s = NULL;
  switch (proto) {


#ifdef PICO_SUPPORT_UDP
  case PICO_PROTO_UDP:
    port = pico_get_sockport(proto, trans->sport);
    break;
#endif

#ifdef PICO_SUPPORT_TCP
  case PICO_PROTO_TCP:
    port = pico_get_sockport(proto, trans->sport);
    break;
#endif

  default:
    /* Protocol not available */
    ret = -1;
  }
  if (port) {
    struct pico_tree_node * index;
    ret = 0;

    pico_tree_foreach(index,&port->socks) {
      s = index->keyValue;
      if (trans->dport == s->remote_port) {
        if (s->wakeup) {
          //dbg("SOCKET ERROR FROM ICMP NOTIFICATION. (icmp code= %d)\n\n", code);
          switch(code) {
            case PICO_ICMP_UNREACH_PROTOCOL:
              pico_err = PICO_ERR_EPROTO;
              break;

            case PICO_ICMP_UNREACH_PORT:
              pico_err = PICO_ERR_ECONNREFUSED;
              break;

            case PICO_ICMP_UNREACH_NET:
            case PICO_ICMP_UNREACH_NET_PROHIB:
            case PICO_ICMP_UNREACH_NET_UNKNOWN:
              pico_err = PICO_ERR_ENETUNREACH;
              break;

            default:
              pico_err = PICO_ERR_EHOSTUNREACH;
          }
          s->wakeup(PICO_SOCK_EV_ERR, s);
        }
        break;
      }
    }
  }
  pico_frame_discard(f);
  return ret;
}

#endif
#endif
