/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef _PICO_DATALINK
#define _PICO_DATALINK
#include <stdint.h>
#include "pico_headers.h"
#include "pico_stack.h"


/* Global router initialization */
void vderouter_init(void);

/* Route management */

uint32_t pico_get_right_localip(struct pico_iface *vif, uint32_t dst);
uint32_t pico_get_netmask(struct pico_iface *vif, uint32_t localip);
uint32_t pico_get_network(uint32_t localip, uint32_t netmask);
uint32_t pico_get_broadcast(uint32_t localip, uint32_t netmask);

int pico_route_add(uint32_t address, uint32_t netmask, uint32_t gateway, uint16_t metric, struct pico_iface *dst);
int pico_route_del(uint32_t address, uint32_t netmask, int metric);
struct pico_route * pico_get_route(uint32_t address);
int pico_default_route(uint32_t gateway, int metric);
uint32_t pico_get_right_localip(struct pico_iface *vif, uint32_t dst);
int pico_ipaddress_is_local(uint32_t addr);
int pico_ipaddress_is_broadcast(uint32_t addr);


/* Interface management */

struct pico_iface *pico_iface_new(char *sock, uint8_t *macaddr);
int pico_iface_address_add(struct pico_iface *iface, uint32_t addr, uint32_t netmask);
int pico_iface_address_del(struct pico_iface *iface, uint32_t addr);
int pico_sendto(struct pico_iface *iface, struct pico_buff *vb, uint8_t *dst);

struct pico_iface *pico_iface_new(char *sock, uint8_t *macaddr);
int pico_iface_address_add(struct pico_iface *iface, uint32_t addr, uint32_t netmask);
int pico_iface_address_del(struct pico_iface *iface, uint32_t addr);
int pico_send(struct pico_iface *iface, struct pico_buff *vb, int len, uint8_t *dst);
int pico_recv(struct pico_iface *iface, struct pico_buff *vb, int len);

/* Thread-loops */
void *pico_core_send_loop(void *);
void *pico_core_recv_loop(void *);
void *pico_core_queuer_loop(void *);

/* timed dequeues (token bucket) */
void pico_timed_dequeue_add(struct pico_queue *q, uint32_t interval);
void pico_timed_dequeue_del(struct pico_queue *q);


/* Filter */
int pico_filter_del(struct pico_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport);
int pico_filter_add(struct pico_iface *src, uint8_t proto,
		uint32_t saddr_address, uint32_t saddr_netmask,
		uint32_t daddr_address, uint32_t daddr_netmask,
		int tos,
		uint16_t sport, uint16_t dport,
		enum filter_action action, uint8_t priority);

int pico_filter(struct pico_buff *buf);

/* Get TCP/UDP header ports */
#define transport_sport(vdb) *((uint16_t *)((unsigned char*)(payload(vdb)) + 0))
#define transport_dport(vdb) *((uint16_t *)((unsigned char*)(payload(vdb)) + 2))

#endif
