/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "pico_stack.h"
#include "vde_headers.h"
#include "pico_queue.h"
#include "pico_packet.h"
#include "pico_icmp.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libvdeplug.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
#include <stdio.h>

struct pico_stack Stack = {};



/* MAC Addresses helpers. */

const uint8_t macaddr_vendor[3] = {0,2,5};

static uint8_t interfaces_list_lenght(void)
{
	uint8_t len = 0;
	struct pico_iface *vif = Stack.iflist;
	while(vif) {
		len++;
		vif = vif->next;
	}
	return len;
}

static void new_macaddress(struct pico_iface *vif)
{
	uint16_t pid = getpid();
	memcpy(vif->macaddr, macaddr_vendor, 3);
	vif->macaddr[3] = (pid & 0xFF00) >> 8;
	vif->macaddr[4] = (pid & 0xFF);
	vif->macaddr[5] = vif->interface_id;
}


/* Queue management */

static void queue_init(struct pico_queue *q)
{
	memset(q, 0, sizeof(struct pico_queue));
	pthread_mutex_init(&q->lock, NULL);
	qunlimited_setup(q);
}

#define microseconds(tv) (unsigned long long)((tv.tv_sec * 1000000) + (tv.tv_usec));

static void *pico_timer_loop(void *arg)
{
	struct timeval now_tv;
	struct timespec interval = {};
	unsigned long long now;
	struct pico_timed_dequeue *cur;
	while(1) {
		gettimeofday(&now_tv, NULL);
		now = microseconds(now_tv);
		cur = Stack.timed_dequeue;
		pthread_mutex_lock(&Stack.global_config_lock);
		while(cur) {
			while (now > (cur->last_out + cur->interval)) {
				if (cur->q) {
					if (cur->q->type == QTYPE_OUT)
						sem_post(&cur->q->semaphore);
					else
						sem_post(cur->q->prio_semaphore);
					cur->last_out += cur->interval;
					if (cur->last_out > now)
						cur->last_out = now;
				}
			}
			cur = cur->next;
		}
		pthread_mutex_unlock(&Stack.global_config_lock);
		interval.tv_sec = 0;
		interval.tv_nsec = Stack.smallest_interval / 1000;
		if (Stack.timed_dequeue) 
			nanosleep(&interval, NULL);
		else
			sleep(2);
	}
	return 0;
}


void pico_timed_dequeue_add(struct pico_queue *q, uint32_t interval)
{
	struct pico_timed_dequeue *new = malloc(sizeof(struct pico_timed_dequeue));
	struct timeval now_tv;
	pthread_mutex_lock(&Stack.global_config_lock);
	gettimeofday(&now_tv, 0);
	if (!new)
		return;
	new->interval = interval;
	new->q = q;
	new->last_out = microseconds(now_tv);
	new->next = Stack.timed_dequeue;
	Stack.timed_dequeue = new;
	if (Stack.smallest_interval > new->interval) {
		Stack.smallest_interval = new->interval;
	}
	pthread_mutex_unlock(&Stack.global_config_lock);
}

void pico_timed_dequeue_del(struct pico_queue *q) 
{
	struct pico_timed_dequeue *prev = NULL, *cur = Stack.timed_dequeue;
	pthread_mutex_lock(&Stack.global_config_lock);
	while(cur) {
		if (cur->q == q) {
			if (!prev)
				Stack.timed_dequeue = cur->next;
			else
				prev->next = cur->next;
			free(cur);
			break;
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Stack.global_config_lock);
}

/* Global router initialization */
void vderouter_init(void)
{
	memset(&Stack, 0, sizeof(Stack));
	pthread_create(&Stack.timer, 0, pico_timer_loop, NULL); 
	pthread_mutex_init(&Stack.global_config_lock, NULL);
	Stack.smallest_interval = 100000;

}

/* Route management */

uint32_t pico_get_right_localip(struct pico_iface *vif, uint32_t dst)
{
	struct pico_ip4address *cur = vif->address_list;
	while(cur) {
		if ((cur->address & cur->netmask) == (dst & cur->netmask))
			return cur->address;
		cur = cur->next;
	}
	return 0U;
}

uint32_t pico_get_netmask(struct pico_iface *vif, uint32_t localip)
{
	struct pico_ip4address *cur = vif->address_list;
	while(cur) {
		if (cur->address == localip)
			return cur->netmask;
		cur = cur->next;
	}
	return 0U;
}

uint32_t pico_get_network(uint32_t localip, uint32_t netmask)
{
	return (localip & netmask);
}

uint32_t pico_get_broadcast(uint32_t localip, uint32_t netmask)
{
	return (localip | (~netmask));
}

/* insert route, ordered by netmask, metric.
 *  Default gw will be the last ones.
 */
int pico_route_add(uint32_t address, uint32_t netmask, uint32_t gateway, uint16_t metric, struct pico_iface *dst)
{
	struct pico_route *cur, *prev, *ro = malloc(sizeof(struct pico_route));
	uint32_t l_addr, l_nm;
	int ret = -1;
	if (!ro)
		return -1;
	pthread_mutex_lock(&Stack.global_config_lock);
	l_addr = ntohl(address);
	l_nm = ntohl(netmask);

	/* Address is "network part" only */
	l_addr &= l_nm;
	ro->dest_addr = htonl(l_addr);
	ro->netmask = netmask;
	ro->gateway = gateway;
	ro->metric = metric;
	if (dst) 
		ro->iface = dst;
	else {
		struct pico_route *next_hop = pico_get_route(gateway);
		if (!next_hop) {
			errno = EHOSTUNREACH;
			goto out_unlock;
		}
		ro->iface = next_hop->iface; 
	}

	/* Is this route already there? */
	cur = Stack.routing_table;
	while(cur) {
		if ((cur->dest_addr == ro->dest_addr) && (cur->netmask == ro->netmask) && (cur->metric == ro->metric)) {
			errno = EEXIST;
			goto out_unlock;
		}
		cur = cur->next;
	}

	cur = Stack.routing_table;
	prev = NULL;
	if (!cur) {
		Stack.routing_table = ro;
		ro->next = NULL;
	} else {
		while(cur) {
			if (ntohl(cur->netmask) < ntohl(ro->netmask) ||
			  ((cur->netmask == ro->netmask) && (cur->metric < ro->metric))) {
				if (!prev) {
					Stack.routing_table = ro;
					ro->next = cur;
					ret = 0; /* Successfully inserted as first member */
					goto out_unlock;
				} else {
					prev->next = ro;
					ro->next = cur;
					ret = 0; /* Successfully inserted between prev and cur */
					goto out_unlock;
				}
			}
			prev = cur;
			cur = cur->next;
		}
		/* if we got here, the current route must be inserted after the last one */
		prev->next = ro;
		ro->next = NULL;
		ret = 0;
	}

out_unlock:
	pthread_mutex_unlock(&Stack.global_config_lock);
	return ret;
}

int pico_route_del(uint32_t address, uint32_t netmask, int metric)
{
	struct pico_route *cur = Stack.routing_table, *prev = NULL;
	int retval = -1;
	pthread_mutex_lock(&Stack.global_config_lock);
	while(cur) {
		if ((cur->dest_addr == address) &&
		 (cur->netmask == netmask) &&
		 (cur->metric == metric)) {
			if (prev) {
				prev->next = cur->next;
			} else {
				Stack.routing_table = cur->next;
			}
			free(cur);
			retval = 0;
			break;
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Stack.global_config_lock);
	return retval;
}

struct pico_route * pico_get_route(uint32_t address)
{
	struct pico_route *cur = Stack.routing_table;
	uint32_t l_addr, r_addr, r_netmask;
	l_addr = ntohl(address);
	while(cur) {
		r_addr = ntohl(cur->dest_addr);
		r_netmask = ntohl(cur->netmask);
		if ((l_addr & r_netmask) == r_addr)
			break;
		cur = cur->next;
	}
	return cur;
}

int pico_default_route(uint32_t gateway, int metric)
{
	struct pico_route *dst = pico_get_route(gateway);
	if (!dst || (!dst->dest_addr) || dst->gateway)
		return -EINVAL;
	return pico_route_add(0, 0, gateway, metric, dst->iface);
}

/* Interface management */

struct pico_iface *pico_iface_new(char *sock, uint8_t *macaddr)
{
	struct pico_iface *vif = (struct pico_iface *) malloc(sizeof(struct pico_iface)), *cur;
    struct vde_open_args open_args={.mode=0700};
	int i;
	if (!vif)
		return NULL;

	pthread_mutex_lock(&Stack.global_config_lock);

	vif->vdec = vde_open(sock, "pico_stack", &open_args); 
	if (vif->vdec == NULL) {
		perror("vde_open");
		free(vif);
		vif = NULL;
		goto out;
	}

	sem_init(&vif->out_q.semaphore, 0, 0);
	sem_init(&vif->prio_semaphore, 0, 0);

	queue_init(&vif->out_q);
	vif->out_q.type = QTYPE_OUT;
	for (i=0; i< PRIO_NUM; i++) {
		queue_init(&(vif->prio_q[i]));
		vif->prio_q[i].type = QTYPE_PRIO;
		vif->prio_q[i].prio_semaphore = &vif->prio_semaphore;
	}

	vif->interface_id = interfaces_list_lenght();
	if (!macaddr)
		new_macaddress(vif);
	else
		memcpy(vif->macaddr, macaddr, 6);
	vif->arp_table = RB_ROOT;
	vif->address_list = NULL;
	vif->router = &Stack;
	vif->next = NULL;
	cur = Stack.iflist;
	strncpy(vif->vde_sock, sock, 1023);
	if(!cur) {
		Stack.iflist = vif;
	} else {
		while(cur->next)
			cur = cur->next;
		cur->next = vif;
	}

out:
	pthread_mutex_unlock(&Stack.global_config_lock);
	return vif;
}

int pico_iface_address_add(struct pico_iface *iface, uint32_t addr, uint32_t netmask)
{
	struct pico_ip4address *address = malloc(sizeof(struct pico_ip4address));
	struct pico_ip4address *cur = iface->address_list;
	if (!address) {
		errno = EINVAL;
		return -1;
	}
	while(cur) {
		if (cur->address == addr) {
			free(address);
			errno = EADDRINUSE;
			return -1;
		}
		cur = cur->next;
	}

	pthread_mutex_lock(&Stack.global_config_lock);
	address->address = addr;
	address->netmask = netmask;
	address->next = iface->address_list;
	iface->address_list = address;
	pthread_mutex_unlock(&Stack.global_config_lock);

	/* Add static route towards neightbors */
	if (addr != (uint32_t) (-1))
		pico_route_add(address->address, address->netmask, 0U, 1, iface);

	return 0;
}

int pico_iface_address_del(struct pico_iface *iface, uint32_t addr)
{
	struct pico_ip4address *cur = iface->address_list, *prev = NULL;
	uint32_t netmask = 0U;
	pthread_mutex_lock(&Stack.global_config_lock);
	while(cur) {
		if (cur->address == addr) {
			if (prev) {
				prev->next = cur->next;
			} else {
				iface->address_list = cur->next;
			}
			netmask = cur->netmask;
			free(cur);
		}
		prev = cur;
		cur = cur->next;
	}
	pthread_mutex_unlock(&Stack.global_config_lock);

	/* Get rid of the previously added route */
	if(netmask) {
		pico_route_del((addr & netmask), netmask, 1);
		return 0;
	} else {
		errno = ENOENT;
		return -1;
	}
}

int pico_sendto(struct pico_iface *iface, struct vde_buff *vb, uint8_t *dst)
{
	struct vde_ethernet_header *eth;
	if (!vb || !dst) {
		errno = EINVAL;
		return -1;
	}
	eth = ethhead(vb);
	memcpy(eth->dst, dst, 6);
	memcpy(eth->src, iface->macaddr, 6);
	enqueue(&(iface->prio_q[vb->priority]), vb);
	return 0;
}


int pico_recv(struct pico_iface *iface, struct vde_buff *vb, int len)
{
	vb->len = vde_recv(iface->vdec, vb->data, len, 0);
	vb->src = iface;
	return vb->len;
}

void *pico_core_send_loop(void *vde_if_arg)
{
	struct pico_iface *vde_if = vde_if_arg;
	struct vde_buff *buf;
	while(1) {
		buf = dequeue(&vde_if->out_q);
		if (!buf)
			continue;
		vde_send(vde_if->vdec, buf->data, buf->len, 0);
		vde_if->stats.sent++;
		free(buf);
	}
}

void *pico_core_recv_loop(void *vde_if_arg)
{
	struct pico_iface *vde_if = vde_if_arg;
	while(1) {
		(void) pico_packet_recv(vde_if, -1);
		vde_if->stats.recvd++;
	}
}

void *pico_core_queuer_loop(void *vde_if_arg)
{
	struct pico_iface *vde_if = vde_if_arg;
	struct vde_buff *buf;
	while(1) {
		buf = prio_dequeue(vde_if);
		if (!buf)
			continue;
		enqueue(&vde_if->out_q, buf);
	}
}

int pico_ipaddress_is_local(uint32_t addr) {
	struct pico_iface *iface = Stack.iflist;
	while (iface) {
		struct pico_ip4address *cur = iface->address_list;
		while(cur) {
			if ((cur->address == addr)|| (cur->address == (uint32_t)(-1))) {
				return 1;
			}
			cur = cur->next;
		}
		iface = iface->next;
	}
	return 0;
}

int pico_ipaddress_is_broadcast(uint32_t addr) 
{
	struct pico_iface *iface = Stack.iflist;
	if (addr == (uint32_t)(-1))
		return 1;
	while (iface) {
		struct pico_ip4address *cur = iface->address_list;
		while(cur) {
			if (((cur->address & cur->netmask) == (addr & cur->netmask)) && ((cur->netmask | addr) == 0xFFFFFFFF)) {
				return 1;
			}
			cur = cur->next;
		}
		iface = iface->next;
	}
	return 0;
}



/* IP filter management */
int pico_filter_del(struct pico_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport)
{
	struct pico_filter *prev = NULL, *search = Stack.filtering_table;
	while(search) {
		if ( (search->src_iface == src) &&
			(search->saddr.address == saddr_address) &&
			(search->saddr.netmask  == saddr_netmask) &&
			(search->daddr.address  == daddr_address) &&
			(search->daddr.netmask  == daddr_netmask) &&
			(search->sport == sport) &&
			(search->dport == dport) &&
			(search->tos == tos)
		) {
			if (!prev) {
				Stack.filtering_table = search->next;
			} else {
				prev->next = search->next;
			}
			free(search);
			return 0;
		}
		prev = search;
		search = search->next;
	}
	errno = ENOENT;
	return -1;
}

int pico_filter_add(struct pico_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport,
		enum filter_action action, uint8_t priority)
{
	struct pico_filter *new = malloc(sizeof(struct pico_filter));
	if (!new)
		return -1;
	new->src_iface = src;
	new->saddr.address = saddr_address;
	new->saddr.netmask = saddr_netmask;
	new->daddr.address = daddr_address;
	new->daddr.netmask = daddr_netmask;
	new->sport = sport;
	new->dport = dport;
	new->tos = tos;
	new->proto = proto;
	new->stats_packets = 0U;
	new->stats_bytes = 0U;
	new->action = action;
	new->next = Stack.filtering_table;
	Stack.filtering_table = new;
	return 0;
}

int pico_filter(struct vde_buff *buf)
{
	struct iphdr *ip = iphead(buf);
	struct pico_filter *selected = NULL, *cur = Stack.filtering_table;
	uint8_t foot[sizeof(struct iphdr) + 8];
	while(cur) {
		if ( (!cur->src_iface || (cur->src_iface == buf->src)) &&
			 (!cur->proto     || (cur->proto == ip->protocol)) &&
			 ( (cur->tos < 0) || ((uint8_t)cur->tos == ip->tos)) &&
			 (!cur->saddr.address || (cur->saddr.address == (cur->saddr.netmask & ip->saddr))) &&
			 (!cur->daddr.address || (cur->daddr.address == (cur->daddr.netmask & ip->daddr))) &&
			 (!cur->sport || (cur->sport == transport_sport(buf))) &&
			 (!cur->dport || (cur->dport == transport_dport(buf)))
			) {
				selected = cur;
				break;
		}
		cur = cur->next;
	}
	if (selected) {
		selected->stats_packets++;
		selected->stats_bytes += buf->len;
		switch(selected->action) {
			case filter_priority:
				buf->priority = selected->priority;
				/* fall through */
			case filter_accept:
				return 0;

			case filter_reject:
				memcpy(foot, footprint(buf), sizeof(struct iphdr) + 8);
				pico_icmp_filter(ip->saddr, foot);
				/* fall through */
			case filter_drop:
				return 1;
			default: 
				return 0;
		}
	}
	return 0; /* Default (no rule set): accept. */
}
