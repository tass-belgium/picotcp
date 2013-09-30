/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Daniele Lacamera
*********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_arp.h"
#include "pico_socket.h"
#ifdef PICO_SUPPORT_OLSR


#define OLSR_MSG_INTERVAL 2000
#define DGRAM_MAX_SIZE 1800
static const struct pico_ip4 HOST_NETMASK = { 0xFFFFFFFF };
#ifndef MIN
# define MIN(a,b) (a<b?a:b)
#endif

#define fresher(a,b) ((a>b) || ((b - a) > 32768))

/* Objects */
struct olsr_route_entry
{
	struct olsr_route_entry         *next;
	long 		                        time_left;
	struct pico_ip4			            destination;
	struct olsr_route_entry         *gateway;
	struct pico_device              *iface;
	uint16_t			                  metric;
	uint8_t				                  link_type;
	struct olsr_route_entry         *children;
	uint16_t                        ansn;
	uint8_t                         lq, nlq;
	uint8_t                         *advertised_tc;
};

struct olsr_dev_entry
{
  struct olsr_dev_entry *next;
  struct pico_device *dev;
};


/* OLSR Protocol */
#define OLSRMSG_HELLO 	0xc9
#define OLSRMSG_MID		0x03
#define OLSRMSG_TC		0xca

#define OLSRLINK_SYMMETRIC 0x06
#define OLSRLINK_UNKNOWN 0x08
#define OLSRLINK_MPR	0x0a

#define OLSR_MAX_DEVICES 8

#define OLSR_PORT (short_be(698))

struct __attribute__((packed)) olsr_link
{
	uint8_t link_code;
	uint8_t reserved;
	uint16_t link_msg_size;
};

struct __attribute__((packed)) olsr_neighbor
{
	uint32_t addr;
	uint8_t  lq;
	uint8_t  nlq;
	uint16_t reserved;
};

struct __attribute__((packed)) olsr_hmsg_hello
{
	uint16_t reserved;
	uint8_t htime;
	uint8_t willingness;
};

struct __attribute__((packed)) olsr_hmsg_tc
{
	uint16_t ansn;
	uint16_t reserved;
};


struct __attribute__((packed)) olsrmsg
{
	uint8_t type;
	uint8_t vtime;
	uint16_t size;
	struct pico_ip4 orig;
	uint8_t ttl;
	uint8_t hop;
	uint16_t seq;
};

struct __attribute__((packed)) olsrhdr
{
	uint16_t len;
	uint16_t seq;
};


struct olsr_setup {
	int n_ifaces;
	struct pico_device *ifaces[OLSR_MAX_DEVICES];
};



/* Globals */
static struct pico_socket *udpsock = NULL;
uint16_t my_ansn = 0;
uint16_t fresh_ansn = 0;
static struct olsr_route_entry  *Local_interfaces = NULL;
static struct olsr_dev_entry    *Local_devices    = NULL;

struct olsr_route_entry *olsr_get_ethentry(struct pico_device *vif)
{
  struct olsr_route_entry *cur = Local_interfaces;
  while(cur) {
    if (cur->iface == vif)
      return cur;
    cur = cur->next;
  }
  return NULL;
}


static struct olsr_route_entry *get_next_hop(struct olsr_route_entry *dst)
{
	struct olsr_route_entry *hop = dst;
	while(hop) {
		if(hop->metric <= 1)
			return hop;
		hop = hop->gateway;
	}
	return NULL;
}

static inline void olsr_route_add(struct olsr_route_entry *el)
{
	struct olsr_route_entry *nexthop;

	if (fresher(fresh_ansn, my_ansn))
		my_ansn = fresh_ansn + 1;
	else
		my_ansn++;

	if (el->gateway) {
		/* 2-hops route or more */
		el->next = el->gateway->children;
		el->gateway->children = el;
		nexthop = get_next_hop(el);
    dbg("[OLSR] Adding route\n");
    pico_ipv4_route_add(el->destination, HOST_NETMASK, nexthop->destination, el->metric, NULL);
		el->link_type = OLSRLINK_MPR;
	} else if (el->iface) {
		/* neighbor */
		struct olsr_route_entry *ei = olsr_get_ethentry(el->iface);
		el->link_type = OLSRLINK_SYMMETRIC;
		if (ei) {
			el->next = ei->children;
			ei->children = el;
		}
	}
}

static inline void olsr_route_del(struct olsr_route_entry *r)
{
	struct olsr_route_entry *cur, *prev = NULL, *lst;
	if (fresher(fresh_ansn, my_ansn))
		my_ansn = fresh_ansn + 1;
	if (r->gateway) {
		lst = r->gateway->children;
	} else if (r->iface) {
		lst = olsr_get_ethentry(r->iface);
	} else {
		lst = Local_interfaces;
	}
	cur = lst, prev = NULL;
	while(cur) {
		if (cur == r) {
			/* found */
			if (r->gateway) {
				pico_ipv4_route_del(r->destination, HOST_NETMASK, r->metric);
				if (!prev)
					r->gateway->children = r->next;
				else
					prev->next = r->next;
			}

			while (r->children) {
				olsr_route_del(r->children);
				/* Orphans must die. */
				free(r->children);
			}
			return;
		}
		prev = cur;
		cur = cur->next;
	}
}

static struct olsr_route_entry *get_route_by_address(struct olsr_route_entry *lst, uint32_t ip)
{
	struct olsr_route_entry *found;
	if(lst) {
		if (lst->destination.addr == ip) {
			return lst;
		}
		found = get_route_by_address(lst->children, ip);
		if (found)
			return found;
		found = get_route_by_address(lst->next, ip);
		if (found)
			return found;
	}
	return NULL;
}

#define OLSR_C_SHIFT 4 /* 1/16 */
#define DEFAULT_VTIME 288UL

uint8_t seconds2olsr(uint32_t seconds)
{
    uint8_t a, b;

    /* find largest b such as seconds/C >= 2^b */
    for (b = 0; b <= 0x0f; b++) {
        if (seconds * 16 < (1u << b)){
            b--;
            break;
        }
    }
    /* compute the expression 16*(T/(C*(2^b))-1), which may not be a
       integer, and round it up.  This results in the value for 'a' */
    a = (seconds / ((1 << b) >> OLSR_C_SHIFT) - 1) << 4;
    //    a = 16 * (seconds / (OSLR_C * (1 << b)) - 1);

    /* if 'a' is equal to 16: increment 'b' by one, and set 'a' to 0 */
    if (16 == a) {
        b++;
        a = 0;
    }
    return (a << 4) + b;
}

uint32_t olsr2seconds(uint8_t olsr)
{
    uint8_t a, b;
    a = olsr >> 4;
    b = olsr & 0x0f;
    return ( (1 << b) + ((a << b) >> 4) ) >> OLSR_C_SHIFT;
}


static void refresh_neighbors(struct pico_device *iface)
{
	struct pico_ip4 neighbors[256];
	int i;
	struct olsr_route_entry *found = NULL, *ancestor = NULL;
	int n_vec_size = pico_arp_get_neighbors(iface, neighbors, 256);

	ancestor = olsr_get_ethentry(iface);
	if (!ancestor)
		return;

	for (i = 0; i < n_vec_size; i++) {
		found = get_route_by_address(Local_interfaces, neighbors[i].addr);
		if (found) {
			if (found->metric > 1) { /* Reposition among neighbors */
				olsr_route_del(found);
				found->gateway = olsr_get_ethentry(iface);
				found->iface = iface;
				found->metric = 1;
				found->lq = 0xFF;
				found->nlq = 0xFF;
				olsr_route_add(found);
			}
			found->link_type = OLSRLINK_SYMMETRIC;
			found->time_left = (OLSR_MSG_INTERVAL << 2);
		} else {
			struct olsr_route_entry *e = pico_zalloc(sizeof (struct olsr_route_entry));
			if (!e) {
				dbg("olsr: adding local route entry");
				return;
			}
			e->destination.addr = neighbors[i].addr;
			e->link_type = OLSRLINK_SYMMETRIC;
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->gateway = olsr_get_ethentry(iface);
			e->iface = iface;
			e->metric = 1;
			e->lq = 0xFF;
			e->nlq = 0xFF;
			olsr_route_add(e);
		}
	}
}

static void olsr_garbage_collector(struct olsr_route_entry *sublist)
{
	if(!sublist)
		return;
	if ((sublist->time_left--) <= 0) {
		olsr_route_del(sublist);
		free(sublist);
		return;
	}
	olsr_garbage_collector(sublist->children);
	olsr_garbage_collector(sublist->next);
}


static void refresh_routes(void)
{
	struct olsr_route_entry *local, *neighbor = NULL;
  struct olsr_dev_entry *icur = Local_devices;

	/* Refresh local entries */

	/* Step 1: set zero expire time for local addresses and neighbors*/
	local = Local_interfaces;
	while(local) {
		local->time_left = 0;
		neighbor = local->children;
		while (neighbor && (neighbor->metric < 2)) {
			//dbg("Setting to zero. Neigh: %08x metric %d\n", neighbor->destination, neighbor->metric);
			neighbor->time_left = 0;
			neighbor = neighbor->next;
		}
		local = local->next;
	}

	/* Step 2: refresh timer for entries that are still valid. 
	 * Add new entries.
	 */
  while(icur) {
    struct pico_ipv4_link *lnk = NULL;
    do { 
      lnk = pico_ipv4_link_by_dev_next(icur->dev, lnk);
      if (!lnk) break;
  		local = olsr_get_ethentry(icur->dev);
  		if (local) {
  			local->time_left = (OLSR_MSG_INTERVAL << 2);
  		} else if (lnk) {
  			struct olsr_route_entry *e = pico_zalloc(sizeof (struct olsr_route_entry));
  			if (!e) {
  				dbg("olsr: adding local route entry");
  				return;
  			}
  			e->destination.addr = lnk->address.addr; /* Always pick the first address */
  			e->time_left = (OLSR_MSG_INTERVAL << 2);
  			e->iface = icur->dev;
  			e->metric = 0;
  			e->lq = 0xFF;
  			e->nlq = 0xFF;
  			e->next = Local_interfaces;
  			Local_interfaces = e;
  		}
    } while (lnk);

		refresh_neighbors(icur->dev);
    icur = icur->next;
	}
}

static int olsr_build_hello_neighbors(uint8_t *buf, int size)
{
	int ret = 0;
	struct olsr_route_entry *local, *neighbor;
	struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
	local = Local_interfaces;
	while (local) {
		neighbor = local->children;
		while (neighbor) {
			struct olsr_link *li = (struct olsr_link *) (buf + ret);
			li->link_code = neighbor->link_type;
			li->reserved = 0;
			li->link_msg_size = short_be(sizeof(struct olsr_neighbor) + sizeof(struct olsr_link));
			ret += sizeof(struct olsr_link);
			dst = (struct olsr_neighbor *) (buf+ret);
			dst->addr = neighbor->destination.addr;
			dst->nlq = neighbor->nlq;
			dst->lq = neighbor->lq;
			dst->reserved = 0;
			ret += sizeof(struct olsr_neighbor);
			if (ret >= size)
				return ret - sizeof(struct olsr_neighbor) - sizeof(struct olsr_link);
			neighbor = neighbor->next;
		}
		local = local->next;
	}
	return ret;
}

static int olsr_build_tc_neighbors(uint8_t *buf, int size)
{
	int ret = 0;
	struct olsr_route_entry *local, *neighbor;
	struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
	local = Local_interfaces;
	while (local) {
		neighbor = local->children;
		while (neighbor) {
			dst->addr = neighbor->destination.addr;
			dst->nlq = neighbor->nlq;
			dst->lq = neighbor->lq;
			dst->reserved = 0;
			ret += sizeof(struct olsr_neighbor);
			dst = (struct olsr_neighbor *) (buf + ret);
			if (ret >= size)
				return ret - sizeof(struct olsr_neighbor);
			neighbor = neighbor->next;
		}
		local = local->next;
	}
	return ret;
}

static int olsr_build_mid(uint8_t *buf, int size, struct pico_device *excluded)
{
	int ret = 0;
	struct olsr_route_entry *local;
	struct pico_ip4 *dst = (struct pico_ip4 *) buf;
	local = Local_interfaces;
	while (local) {
		if (local->iface != excluded) {
			dst->addr = local->destination.addr;
			ret += sizeof(uint32_t);
			dst = (struct pico_ip4 *) (buf + ret);
			if (ret >= size)
				return ret - sizeof(uint32_t);
		}
		local = local->next;
	}
	return ret;
}

static uint16_t pkt_counter = 0;
static void olsr_make_dgram(struct pico_device *pdev, int full)
{
	uint8_t dgram[DGRAM_MAX_SIZE];
	int size = 0, r;
	struct pico_ipv4_link *ep;
	struct olsrhdr *ohdr;
	struct pico_ip4 bcast;
	struct olsrmsg *msg_hello, *msg_mid, *msg_tc;
	struct olsr_hmsg_hello *hello;
	struct olsr_hmsg_tc *tc;
	static uint8_t hello_counter = 0, mid_counter = 0, tc_counter = 0;

	ohdr = (struct olsrhdr *)dgram;
	size += sizeof(struct olsrhdr);
  ep = pico_ipv4_link_by_dev(pdev);
	if (!ep)
		return;
  bcast.addr = (ep->netmask.addr & ep->address.addr) | (~ep->netmask.addr);

	/* HELLO Message */

	msg_hello = (struct olsrmsg *) (dgram + size);
	size += sizeof(struct olsrmsg);
	msg_hello->type = OLSRMSG_HELLO;
	msg_hello->vtime = seconds2olsr(DEFAULT_VTIME);
	msg_hello->orig.addr = ep->address.addr;
	msg_hello->ttl = 1;
	msg_hello->hop = 0;
	msg_hello->seq = short_be(hello_counter++);
	hello = (struct olsr_hmsg_hello *)(dgram + size);
	size += sizeof(struct olsr_hmsg_hello);
	hello->reserved = 0;
	hello->htime = 0x05; /* Todo: find and define values */
	hello->willingness = 0x07;
	r = olsr_build_hello_neighbors(dgram + size, DGRAM_MAX_SIZE - size);
	if (r < 0) {
		dbg("Building hello message");
		return;
	}
	size += r;
	msg_hello->size = short_be(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello) + r);

  if (full) {

  	/* MID Message */
  
  	msg_mid = (struct olsrmsg *)(dgram + size);
  	size += sizeof(struct olsrmsg);
  	msg_mid->type = OLSRMSG_MID;
  	msg_mid->vtime = seconds2olsr(60);
  	msg_mid->orig.addr = ep->address.addr;
  	msg_mid->ttl = 0xFF;
  	msg_mid->hop = 0;
  	msg_mid->seq = short_be(mid_counter++);
  	r = olsr_build_mid(dgram + size, DGRAM_MAX_SIZE - size, pdev);
  	if (r < 0) {
  		dbg("Building mid message");
  		return;
  	}
  	if (r == 0) {
  		size -= sizeof(struct olsrmsg);
  	} else {
  		size += r;
  		msg_mid->size = short_be(sizeof(struct olsrmsg) + r);
  	}
  
  	msg_tc = (struct olsrmsg *) (dgram + size);
  	size += sizeof(struct olsrmsg);
  	msg_tc->type = OLSRMSG_TC;
  	msg_tc->vtime = seconds2olsr(DEFAULT_VTIME); 
  	msg_tc->orig.addr = ep->address.addr;
  	msg_tc->ttl = 0xFF;
  	msg_tc->hop = 0;
  	msg_tc->seq = short_be(tc_counter++);
  	tc = (struct olsr_hmsg_tc *)(dgram + size);
  	size += sizeof(struct olsr_hmsg_tc);
  	tc->ansn = short_be(my_ansn);
  	r = olsr_build_tc_neighbors(dgram + size, DGRAM_MAX_SIZE  - size);
  	if (r < 0) {
  		dbg("Building tc message");
  		return;
  	}
  	size += r;
  	msg_tc->size = short_be(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_tc) + r);
  } /*if full */

	/* Finalize olsr packet */
	ohdr->len = short_be(size);
	ohdr->seq = short_be(pkt_counter++);

	/* Send the thing out */
  if  (0 > pico_socket_sendto(udpsock, dgram, size, &bcast, OLSR_PORT)) {
	}
  dbg("Sent %s packet\n", full!=0?"FULL":"HELLO");
}

static inline void arp_storm(struct pico_ip4 *addr)
{
  struct olsr_dev_entry *icur = Local_devices;
  while(icur) {
		pico_arp_query(icur->dev, addr);
    icur = icur->next;
	}
}

static void recv_mid(uint8_t *buffer, int len, struct olsr_route_entry *origin) 
{
	int parsed = 0;
	uint32_t *address;
	struct olsr_route_entry *e;

	if (len % sizeof(uint32_t)) /*drop*/
		return;

	while (len > parsed) {
		address = (uint32_t *)(buffer + parsed);
		e = get_route_by_address(Local_interfaces, *address);
		if (!e) {
			e = pico_zalloc(sizeof(struct olsr_route_entry));
			if (!e) {
				dbg("olsr allocating route");
				return;
			}
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->destination.addr = *address;
			e->gateway = origin;
			e->iface = origin->iface;
			e->metric = origin->metric + 1;
			e->lq = origin->lq;
			e->nlq = origin->nlq;
			olsr_route_add(e);
			arp_storm(&e->destination);
		} else if (e->metric > (origin->metric + 1)) {
			olsr_route_del(e);
			e->metric = origin->metric;
			e->gateway = origin;
			olsr_route_add(e);
		}
		parsed += sizeof(uint32_t);
	}
}

static void recv_hello(uint8_t *buffer, int len, struct olsr_route_entry *origin)
{
	struct olsr_link *li;
	struct olsr_route_entry *e;
	int parsed = 0;
	struct olsr_neighbor *neigh;

	if (!origin)
		return;

	while (len > parsed) {
		li = (struct olsr_link *) buffer;
		neigh = (struct olsr_neighbor *)(buffer + parsed + sizeof(struct olsr_link));
		parsed += short_be(li->link_msg_size);
		e = get_route_by_address(Local_interfaces, neigh->addr);
		if (!e) {
			e = pico_zalloc(sizeof(struct olsr_route_entry));
			if (!e) {
				dbg("olsr allocating route");
				return;
			}
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->destination.addr = neigh->addr;
			e->gateway = origin;
			e->iface = origin->iface;
			e->metric = origin->metric + 1;
			e->link_type = OLSRLINK_UNKNOWN;
			e->lq = MIN(origin->lq, neigh->lq);
			e->nlq = MIN(origin->nlq, neigh->nlq);
			olsr_route_add(e);
			arp_storm(&e->destination);
		} else if ((e->gateway != origin) && (e->metric > (origin->metric + 1))) {
			olsr_route_del(e);
			e->metric = origin->metric + 1;
			e->gateway = origin;
			olsr_route_add(e);
		}
	}
}

static int reconsider_topology(uint8_t *buf, int size, struct olsr_route_entry *e)
{
	struct olsr_hmsg_tc *tc = (struct olsr_hmsg_tc *) buf;
	uint16_t new_ansn = short_be(tc->ansn);
	int parsed = sizeof(struct olsr_hmsg_tc);
	struct olsr_route_entry *rt;
	struct olsr_neighbor *n;

	if (e->advertised_tc && fresher(new_ansn, e->ansn))
	{
		free(e->advertised_tc);
		e->advertised_tc = NULL;
	}

	if (fresher(new_ansn, fresh_ansn)) {
		fresh_ansn = new_ansn;
	}

	if (!e->advertised_tc) {
		e->advertised_tc = pico_zalloc(size);
		if (!e) {
			dbg("Allocating forward packet");
			return -1;
		}
		memcpy(e->advertised_tc, buf, size);
		e->ansn = new_ansn;
		while (parsed < size) {
			n = (struct olsr_neighbor *) (buf + parsed);
			parsed += sizeof(struct olsr_neighbor);
			rt = get_route_by_address(Local_interfaces, n->addr);
			if (rt && (rt->gateway == e)) {
				/* Refresh existing node */
				rt->time_left = e->time_left;
			} else if (!rt || (rt->metric > (e->metric + 1)) || (rt->nlq < n->nlq)) {
				if (!rt) {
					rt = pico_zalloc(sizeof (struct olsr_route_entry));
					rt->destination.addr = n->addr;
				} else {
					olsr_route_del(rt);
				}
				rt->link_type = OLSRLINK_UNKNOWN;
				rt->iface = e->iface;
				rt->gateway = e;
				rt->metric = e->metric + 1;
				rt->lq = n->lq;
				rt->nlq = n->nlq;
				rt->time_left = e->time_left;
				olsr_route_add(rt);
			}
		}
		return 1;
	} else {
		return 0;
	}
}

static void olsr_recv(uint8_t *buffer, int len)
{
	struct olsrmsg *msg;
	struct olsrhdr *outohdr, *oh = (struct olsrhdr *) buffer;
	struct olsr_route_entry *ancestor;
	int parsed = 0;
	uint8_t outmsg[DGRAM_MAX_SIZE];
	uint32_t outsize = 0;
	if (len != short_be(oh->len)) {
		return;
	}
	parsed += sizeof(struct olsrhdr);

	outohdr = (struct olsrhdr *)outmsg;
	outsize += sizeof(struct olsrhdr);

	while (len > parsed) {
		struct olsr_route_entry *origin;
		msg = (struct olsrmsg *) (buffer + parsed);
		origin = get_route_by_address(Local_interfaces, msg->orig.addr);
		if (!origin) {
			/* Discard this msg while it is not from known host */
			arp_storm(&msg->orig);
			parsed += short_be(msg->size);
			continue;
		}
		/* We know this is a Master host and a neighbor */
		origin->link_type = OLSRLINK_MPR;
		origin->time_left = olsr2seconds(msg->vtime);
		switch(msg->type) {
			case OLSRMSG_HELLO:
				ancestor = olsr_get_ethentry(origin->iface);
				if ((origin->metric > 1) && ancestor) {
					olsr_route_del(origin);
					origin->gateway = ancestor;
					origin->metric = 1;
					olsr_route_add(origin);
				}
				recv_hello(buffer + parsed + sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello),
					short_be(msg->size) - (sizeof(struct olsrmsg)) - sizeof(struct olsr_hmsg_hello),
					origin);
				msg->ttl = 0;
				break;
			case OLSRMSG_MID:
				recv_mid(buffer + parsed + sizeof(struct olsrmsg), short_be(msg->size) - (sizeof(struct olsrmsg)), origin);
				break;
			case OLSRMSG_TC:
				if (reconsider_topology(buffer + parsed + sizeof(struct olsrmsg), short_be(msg->size) - (sizeof(struct olsrmsg)), origin) < 1)
					msg->ttl = 0;
				else {
					msg->hop = origin->metric;
				}
				break;
			default:
				return;
		}
		if ((--msg->ttl) > 0) {
			memcpy(outmsg + outsize, msg, short_be(msg->size));
			outsize += short_be(msg->size);
		}
		parsed += short_be(msg->size);
	}

	if (outsize > sizeof(struct olsrhdr)) {
		struct pico_ip4 bcast;
		struct pico_ipv4_link *addr;
		struct olsr_dev_entry *pdev = Local_devices;
		/* Finalize FWD packet */
		outohdr->len = short_be(outsize);
		outohdr->seq = short_be(pkt_counter++);


		/* Send the thing out */
   while(pdev) { 
      addr = pico_ipv4_link_by_dev(pdev->dev);
			if (!addr)
				continue;
      bcast.addr = (addr->netmask.addr & addr->address.addr) | (~addr->netmask.addr);
			if ( 0 > pico_socket_sendto(udpsock, outmsg, outsize, &bcast, OLSR_PORT) ) {
				dbg("olsr send");
			}
      pdev = pdev->next;
		}
	}
}

static void wakeup(uint16_t ev, struct pico_socket *s)
{
  unsigned char recvbuf[DGRAM_MAX_SIZE];
  int r = 0;
  struct pico_ip4 ANY = {0};
  uint16_t port = OLSR_PORT;

  if (ev & PICO_SOCK_EV_RD) {
    r = pico_socket_recv(s, recvbuf, DGRAM_MAX_SIZE);
    if (r > 0)
      olsr_recv(recvbuf, r);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    pico_socket_close(udpsock);
    udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
    if (udpsock)
      pico_socket_bind(udpsock, &ANY, &port);
  }
}

static void olsr_tick(uint32_t when, void *unused)
{
  struct olsr_dev_entry *d;
  static int full = 0;
  (void)when;
  (void)unused;
  olsr_garbage_collector(Local_interfaces);
	refresh_routes();
  d = Local_devices;
  while(d) {
		olsr_make_dgram(d->dev, full);
    d = d->next;
  }
  if (full++ > 0)
    full = 0;
  pico_timer_add(1000, &olsr_tick, NULL);
}


/* Public interface */

void pico_olsr_init(void)
{
  struct pico_ip4 ANY = {0};
  uint16_t port = OLSR_PORT;
  dbg("OLSR initialized.\n");
  if (!udpsock) {
    udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
    if (udpsock)
      pico_socket_bind(udpsock, &ANY, &port);
  }
  pico_timer_add(100, &olsr_tick, NULL);
}

int pico_olsr_add(struct pico_device *dev)
{
  struct pico_ipv4_link *lnk = NULL;
  struct olsr_dev_entry *od; 
  if (!dev) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  dbg("OLSR: Adding device %s\n", dev->name);
  od = pico_zalloc(sizeof(struct olsr_dev_entry));
  if (!od) {
     pico_err = PICO_ERR_ENOMEM;
     return -1;
  }
  od->dev = dev;
  od->next = Local_devices;
  Local_devices = od;

  do {
    lnk = pico_ipv4_link_by_dev_next(dev, lnk);
    if (lnk) {
      struct olsr_route_entry *e = pico_zalloc(sizeof(struct olsr_route_entry));
      dbg("OLSR: Found IP address %08x\n", long_be(lnk->address.addr));
      if (!e) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
      }
      e->destination.addr = lnk->address.addr;
      e->link_type = OLSRLINK_SYMMETRIC;
      e->time_left = (OLSR_MSG_INTERVAL << 2);
      e->gateway = NULL;
      e->iface = dev;
			e->metric = 0;
			e->lq = 0xFF;
			e->nlq = 0xFF;
			e->next = Local_interfaces;
			Local_interfaces = e;

    }
  } while(lnk);
  return 0;
}

#endif
