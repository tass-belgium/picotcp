/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef __VDER_ARP
#define __VDER_ARP
#include "vde_router.h"
#include <stdint.h>

/* Interface */
struct vder_arp_entry {
	struct rb_node rb_node;
	uint32_t ipaddr;
	uint8_t macaddr[6];
};

void vder_add_arp_entry(struct vder_iface *vif, struct vder_arp_entry *p);
struct vder_arp_entry *vder_get_arp_entry(struct vder_iface *vif, uint32_t addr);
size_t vder_arp_query(struct vder_iface *oif, uint32_t tgt);
size_t vder_arp_reply(struct vder_iface *oif, struct vde_buff *vdb);
/* Parse an incoming arp packet */;
int vder_parse_arp(struct vder_iface *vif, struct vde_buff *vdb);


/* O(N) search by macaddr (required by dhcp server) */
struct vder_arp_entry *vder_arp_get_record_by_macaddr(struct vder_iface *vif, uint8_t *mac);

/* O(N) list of neighbors (required by olsr) */
int vder_arp_get_neighbors(struct vder_iface *vif, uint32_t *neighbors, int vector_size);

#endif

