/* VDE_ROUTER (C) 2007:2012 Daniele Lacamera
 *
 * Time-conversion functions by Julien Duraj <julien@duraj.fr>
 * Licensed under the GPLv2
 * OLSR implementation loosely based on RFC3626 :)
 *
 */
#include "vder_udp.h"
#include "vder_arp.h"
#include "vder_olsr.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


#define OLSR_MSG_INTERVAL 2000
#define DGRAM_MAX_SIZE 1800
#define HOST_NETMASK (htonl(0xFFFFFFFF))
#ifndef MIN
# define MIN(a,b) (a<b?a:b)
#endif

#define fresher(a,b) ((a>b) || ((b - a) > 32768))

static struct vder_udp_socket *udpsock;
static struct olsr_setup *settings;
uint16_t my_ansn = 0;
uint16_t fresh_ansn = 0;

struct olsr_route_entry
{
	struct olsr_route_entry *next;
	long 		time_left;
	uint32_t			destination;
	struct olsr_route_entry *gateway;
	struct vder_iface 	*iface;
	uint16_t			metric;
	uint8_t				link_type;
	struct olsr_route_entry *children;
	uint16_t ansn;
	uint8_t lq, nlq;
	uint8_t *advertised_tc;
};

static struct olsr_route_entry *Local_interfaces;

struct olsr_route_entry *olsr_get_ethentry(struct vder_iface *vif)
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
		vder_route_add(el->destination, HOST_NETMASK, nexthop->destination, el->metric, NULL);
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
				vder_route_del(r->destination, HOST_NETMASK, r->metric);

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
		if (lst->destination == ip) {
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

#define OSLR_C 1/16.0
#define DEFAULT_VTIME 288UL

uint8_t seconds2olsr(uint32_t seconds)
{
    uint8_t a, b;

    /* find largest b such as seconds/C >= 2^b */
    for (b = 0; b <= 0x0f; b++) {
        if (seconds * 16 < (1 << b)){
            b--;
            break;
        }
    }
    /* compute the expression 16*(T/(C*(2^b))-1), which may not be a
       integer, and round it up.  This results in the value for 'a' */
    a = 16 * (seconds / (OSLR_C * (1 << b)) - 1);

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
    return OSLR_C * (1 + a/16.0) * (1 << b);
}


static void refresh_neighbors(struct vder_iface *iface)
{
	uint32_t neighbors[256];
	int i;
	struct olsr_route_entry *found = NULL, *ancestor = NULL;
	int n_vec_size = vder_arp_get_neighbors(iface, neighbors, 256);

	ancestor = olsr_get_ethentry(iface);
	if (!ancestor)
		return;

	for (i = 0; i < n_vec_size; i++) {
		found = get_route_by_address(Local_interfaces, neighbors[i]);
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
			struct olsr_route_entry *e = malloc(sizeof (struct olsr_route_entry));
			if (!e) {
				perror("olsr: adding local route entry");
				return;
			}
			memset(e, 0, sizeof(struct olsr_route_entry));
			e->destination = neighbors[i];
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
	int i;
	struct olsr_route_entry *local, *neighbor = NULL;

	/* Refresh local entries */

	/* Step 1: set zero expire time for local addresses and neighbors*/
	local = Local_interfaces;
	while(local) {
		local->time_left = 0;
		neighbor = local->children;
		while (neighbor && (neighbor->metric < 2)) {
			//printf("Setting to zero. Neigh: %08x metric %d\n", neighbor->destination, neighbor->metric);
			neighbor->time_left = 0;
			neighbor = neighbor->next;
		}
		local = local->next;
	}

	/* Step 2: refresh timer for entries that are still valid. 
	 * Add new entries.
	 */
	for (i = 0; i < settings->n_ifaces; i++) {
		struct vder_iface *icur = settings->ifaces[i];
		local = olsr_get_ethentry(icur);
		if (local) {
			local->time_left = (OLSR_MSG_INTERVAL << 2);
		} else if (icur->address_list) {
			struct olsr_route_entry *e = malloc(sizeof (struct olsr_route_entry));
			if (!e) {
				perror("olsr: adding local route entry");
				return;
			}
			memset(e, 0, sizeof(struct olsr_route_entry));
			e->destination = icur->address_list->address; /* Always pick the first address */
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->iface = icur;
			e->metric = 0;
			e->lq = 0xFF;
			e->nlq = 0xFF;
			e->next = Local_interfaces;
			Local_interfaces = e;
		}
		refresh_neighbors(icur);
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
			li->link_msg_size = htons(sizeof(struct olsr_neighbor) + sizeof(struct olsr_link));
			ret += sizeof(struct olsr_link);
			dst = (struct olsr_neighbor *) (buf+ret);
			dst->addr = neighbor->destination;
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
			dst->addr = neighbor->destination;
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

static int olsr_build_mid(uint8_t *buf, int size, struct vder_iface *excluded)
{
	int ret = 0;
	struct olsr_route_entry *local;
	uint32_t *dst = (uint32_t *) buf;
	local = Local_interfaces;
	while (local) {
		if (local->iface != excluded) {
			*dst = local->destination;
			ret += sizeof(uint32_t);
			dst = (uint32_t *) (buf + ret);
			if (ret >= size)
				return ret - sizeof(uint32_t);
		}
		local = local->next;
	}
	return ret;
}

static uint16_t pkt_counter = 0;
static void olsr_make_dgram(struct vder_iface *vif)
{
	uint8_t dgram[DGRAM_MAX_SIZE];
	int size = 0, r;
	struct vder_ip4address *ep;
	struct olsrhdr *ohdr;
	uint32_t netmask, bcast;
	struct olsrmsg *msg_hello, *msg_mid, *msg_tc;
	struct olsr_hmsg_hello *hello;
	struct olsr_hmsg_tc *tc;
	static uint8_t hello_counter = 0, mid_counter = 0, tc_counter = 0;

	ohdr = (struct olsrhdr *)dgram;
	size += sizeof(struct olsrhdr);

	ep = vif->address_list; /* Take first address */
	if (!ep)
		return;
	netmask = vder_get_netmask(vif, ep->address);
	bcast = vder_get_broadcast(ep->address, netmask);



	/* HELLO Message */

	msg_hello = (struct olsrmsg *) (dgram + size);
	size += sizeof(struct olsrmsg);
	msg_hello->type = OLSRMSG_HELLO;
	msg_hello->vtime = seconds2olsr(DEFAULT_VTIME);
	msg_hello->orig = ep->address;
	msg_hello->ttl = 1;
	msg_hello->hop = 0;
	msg_hello->seq = htons(hello_counter++);
	hello = (struct olsr_hmsg_hello *)(dgram + size);
	size += sizeof(struct olsr_hmsg_hello);
	hello->reserved = 0;
	hello->htime = 0x05; /* Todo: find and define values */
	hello->willingness = 0x07;
	r = olsr_build_hello_neighbors(dgram + size, DGRAM_MAX_SIZE - size);
	if (r < 0) {
		perror("Building hello message");
		return;
	}
	size += r;
	msg_hello->size = htons(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello) + r);

	/* MID Message */

	msg_mid = (struct olsrmsg *)(dgram + size);
	size += sizeof(struct olsrmsg);
	msg_mid->type = OLSRMSG_MID;
	msg_mid->vtime = seconds2olsr(60);
	msg_mid->orig = ep->address;
	msg_mid->ttl = 0xFF;
	msg_mid->hop = 0;
	msg_mid->seq = htons(mid_counter++);
	r = olsr_build_mid(dgram + size, DGRAM_MAX_SIZE - size, vif);
	if (r < 0) {
		perror("Building mid message");
		return;
	}
	if (r == 0) {
		size -= sizeof(struct olsrmsg);
	} else {
		size += r;
		msg_mid->size = htons(sizeof(struct olsrmsg) + r);
	}

	msg_tc = (struct olsrmsg *) (dgram + size);
	size += sizeof(struct olsrmsg);
	msg_tc->type = OLSRMSG_TC;
	msg_tc->vtime = seconds2olsr(DEFAULT_VTIME); 
	msg_tc->orig = ep->address;
	msg_tc->ttl = 0xFF;
	msg_tc->hop = 0;
	msg_tc->seq = htons(tc_counter++);
	tc = (struct olsr_hmsg_tc *)(dgram + size);
	size += sizeof(struct olsr_hmsg_tc);
	tc->ansn = htons(my_ansn);
	r = olsr_build_tc_neighbors(dgram + size, DGRAM_MAX_SIZE  - size);
	if (r < 0) {
		perror("Building tc message");
		return;
	}
	size += r;
	msg_tc->size = htons(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_tc) + r);

	/* Finalize olsr packet */
	ohdr->len = htons(size);
	ohdr->seq = htons(pkt_counter++);

	/* Send the thing out */
	if ( 0 > vder_udpsocket_sendto_broadcast(udpsock, dgram, size, vif, bcast, OLSR_PORT) ) {
		perror("olsr send");
	}
}

static inline void arp_storm(uint32_t addr)
{
	int i;
	for (i = 0; i < settings->n_ifaces; i++) {
		vder_arp_query(settings->ifaces[i], addr);
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
			e = malloc(sizeof(struct olsr_route_entry));
			if (!e) {
				perror("olsr allocating route");
				return;
			}
			memset(e, 0, sizeof(struct olsr_route_entry));
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->destination = *address;
			e->gateway = origin;
			e->iface = origin->iface;
			e->metric = origin->metric + 1;
			e->lq = origin->lq;
			e->nlq = origin->nlq;
			olsr_route_add(e);
			arp_storm(e->destination);
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
		parsed += ntohs(li->link_msg_size);
		e = get_route_by_address(Local_interfaces, neigh->addr);
		if (!e) {
			e = malloc(sizeof(struct olsr_route_entry));
			if (!e) {
				perror("olsr allocating route");
				return;
			}
			memset(e, 0, sizeof(struct olsr_route_entry));
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->destination = neigh->addr;
			e->gateway = origin;
			e->iface = origin->iface;
			e->metric = origin->metric + 1;
			e->link_type = OLSRLINK_UNKNOWN;
			e->lq = MIN(origin->lq, neigh->lq);
			e->nlq = MIN(origin->nlq, neigh->nlq);
			olsr_route_add(e);
			arp_storm(e->destination);
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
	uint16_t new_ansn = ntohs(tc->ansn);
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
		e->advertised_tc = malloc(size);
		if (!e) {
			perror("Allocating forward packet");
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
					rt = malloc(sizeof (struct olsr_route_entry));
					memset(rt, 0, sizeof(struct olsr_route_entry));
					rt->destination = n->addr;
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
	struct olsr_hmsg_tc *msg_tc;
	struct olsrhdr *outohdr, *oh = (struct olsrhdr *) buffer;
	struct olsr_route_entry *ancestor;
	int parsed = 0;
	uint8_t outmsg[DGRAM_MAX_SIZE];
	int outsize = 0;
	if (len != ntohs(oh->len)) {
		return;
	}
	parsed += sizeof(struct olsrhdr);

	outohdr = (struct olsrhdr *)outmsg;
	outsize += sizeof(struct olsrhdr);

	while (len > parsed) {
		struct olsr_route_entry *origin;
		msg = (struct olsrmsg *) (buffer + parsed);
		origin = get_route_by_address(Local_interfaces, msg->orig);
		if (!origin) {
			/* Discard this msg while it is not from known host */
			arp_storm(msg->orig);
			parsed += ntohs(msg->size);
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
					ntohs(msg->size) - (sizeof(struct olsrmsg)) - sizeof(struct olsr_hmsg_hello),
					origin);
				msg->ttl = 0;
				break;
			case OLSRMSG_MID:
				recv_mid(buffer + parsed + sizeof(struct olsrmsg), ntohs(msg->size) - (sizeof(struct olsrmsg)), origin);
				break;
			case OLSRMSG_TC:
				msg_tc = (struct olsr_hmsg_tc *) (buffer + parsed);
				if (reconsider_topology(buffer + parsed + sizeof(struct olsrmsg), ntohs(msg->size) - (sizeof(struct olsrmsg)), origin) < 1)
					msg->ttl = 0;
				else {
					msg->hop = origin->metric;
				}
				break;
			default:
				return;
		}
		if ((--msg->ttl) > 0) {
			memcpy(outmsg + outsize, msg, ntohs(msg->size));
			outsize += ntohs(msg->size);
		}
		parsed += ntohs(msg->size);
	}

	if (outsize > sizeof(struct olsrhdr)) {
		int j;
		uint32_t netmask, bcast;
		struct vder_ip4address *addr;
		struct vder_iface *vif;
		/* Finalize FWD packet */
		outohdr->len = htons(outsize);
		outohdr->seq = htons(pkt_counter++);


		/* Send the thing out */
		for (j = 0; j < settings->n_ifaces; j++) {
			vif = settings->ifaces[j];
			addr = vif->address_list; /* Take first address */
			if (!addr)
				continue;
			netmask = vder_get_netmask(vif, addr->address);
			bcast = vder_get_broadcast(addr->address, netmask);
			if ( 0 > vder_udpsocket_sendto_broadcast(udpsock, outmsg, outsize, vif, bcast, OLSR_PORT) ) {
				perror("olsr send");
			}
		}
	}
}


void *vder_olsr_loop(void *olsr_settings)
{
	uint32_t from_ip;
	uint16_t from_port;
	unsigned char buffer[DGRAM_MAX_SIZE];
	int len;
	int i;
	struct timeval now, last_out;

	settings = (struct olsr_setup *) olsr_settings;
	if(settings->n_ifaces <= 0)
		return NULL;
	if (!udpsock)
		udpsock = vder_udpsocket_open(OLSR_PORT);
	if (!udpsock)
		return NULL;

	for (i = 0; i < settings->n_ifaces; i++) {
		struct vder_ip4address *a = settings->ifaces[i]->address_list;
		while(a) {
			struct olsr_route_entry *e = malloc(sizeof(struct olsr_route_entry));
			if (!e) {
				perror("initializing interfaces");
				return NULL;
			}
			memset(e, 0, sizeof(struct olsr_route_entry));
			e->destination = a->address;
			e->link_type = OLSRLINK_SYMMETRIC;
			e->time_left = (OLSR_MSG_INTERVAL << 2);
			e->gateway = NULL;
			e->iface = settings->ifaces[i];
			e->metric = 0;
			e->lq = 0xFF;
			e->nlq = 0xFF;
			e->next = Local_interfaces;
			Local_interfaces = e;
			a = a->next;
		}
	}

	gettimeofday(&last_out, NULL);
	refresh_routes();

	while(1) {
		len = vder_udpsocket_recvfrom(udpsock, buffer, DGRAM_MAX_SIZE, &from_ip, &from_port, 100);
		if (len < 0) {
			perror("udp recv");
			return NULL;
		}
		if ((len > 0) && (from_port == OLSR_PORT)) {
			olsr_recv(buffer, len);
		}
		usleep(200000);
		gettimeofday(&now, NULL);
		if (last_out.tv_sec == now.tv_sec)
			continue;
		/* Remove expired entries */
		olsr_garbage_collector(Local_interfaces);
		refresh_routes();
		last_out = now;
		for (i = 0; i < settings->n_ifaces; i++)
			olsr_make_dgram(settings->ifaces[i]);
	}
}

