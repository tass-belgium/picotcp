/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "vde_router.h"
#include "vder_arp.h"
#include "vde_headers.h"
#include "vder_datalink.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "rbtree.h"

void vder_add_arp_entry(struct vder_iface *vif, struct vder_arp_entry *p)
{
	struct rb_node **link, *parent;
	uint32_t hostorder_ip = ntohl(p->ipaddr);
	link = &vif->arp_table.rb_node;
	parent = *link;
	while (*link) {
		struct vder_arp_entry *entry;
		parent = *link;
		entry = rb_entry(parent, struct vder_arp_entry, rb_node);
		if (ntohl(entry->ipaddr) > hostorder_ip) {
			link = &(*link)->rb_left;
		} else if (ntohl(entry->ipaddr) < hostorder_ip){
			link = &(*link)->rb_right;
		} else {
			/* Update existing entry */
			memcpy(entry->macaddr,p->macaddr,6);
			return;
		}
	}
	rb_link_node(&p->rb_node, parent, link);
	rb_insert_color(&p->rb_node, &vif->arp_table);
}

struct vder_arp_entry *vder_get_arp_entry(struct vder_iface *vif, uint32_t addr)
{
	struct rb_node *node;
	struct vder_arp_entry *found=NULL;
	uint32_t hostorder_ip = ntohl(addr);
	node = vif->arp_table.rb_node;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (ntohl(entry->ipaddr) > hostorder_ip)
			node = node->rb_left;
		else if (ntohl(entry->ipaddr) < hostorder_ip)
			node = node->rb_right;
		else {
			found = entry;
			break;
		}
	}
	return found;
}

/**
 * Prepare and send an arp query
 */
size_t vder_arp_query(struct vder_iface *oif, uint32_t tgt)
{
	struct vde_ethernet_header *vdeh;
	struct vde_arp_header *ah;
	struct vde_buff *vdb;

	vdb = (struct vde_buff *) malloc(sizeof(struct vde_buff) + 60);
	vdb->len = 60;

	/* set frame type to ARP */
	vdeh = ethhead(vdb);
	vdeh->buftype = htons(PTYPE_ARP);

	/* build arp payload */
	ah = arphead(vdb);
	ah->htype = htons(HTYPE_ETH);
	ah->ptype = htons(PTYPE_IP);
	ah->hsize = ETHERNET_ADDRESS_SIZE;
	ah->psize = IP_ADDRESS_SIZE;
	ah->opcode = htons(ARP_REQUEST);
	memcpy(ah->s_mac, oif->macaddr,6);
	ah->s_addr = vder_get_right_localip(oif, tgt); 
	if (ah->s_addr == 0) {
		if (oif->address_list) 
			ah->s_addr = oif->address_list->address;
		else
			return -1;
	}
	memset(ah->d_mac,0,6);
	ah->d_addr = tgt;
	vdb->priority = PRIO_ARP;
	return vder_sendto(oif, vdb, ETH_BCAST);
}

/**
 * Reply to given arp request, if needed
 */
size_t vder_arp_reply(struct vder_iface *oif, struct vde_buff *vdb)
{
	struct vde_arp_header *ah;
	uint32_t ipaddr_tmp;
	struct vde_buff *vdb_copy;
	ah = arphead(vdb);
	ah->opcode = htons(ARP_REPLY);
	memcpy(ah->d_mac, ah->s_mac, 6);
    memcpy(ah->s_mac, oif->macaddr,6);
	ipaddr_tmp = ah->s_addr;
	ah->s_addr = ah->d_addr;
	ah->d_addr = ipaddr_tmp;
	vdb_copy = malloc(sizeof(struct vde_buff) + vdb->len);
	memcpy(vdb_copy, vdb, (sizeof(struct vde_buff) + vdb->len));
	vdb->priority = PRIO_ARP;
	return vder_sendto(oif, vdb_copy, ah->d_mac);
}

/* Parse an incoming arp packet */
int vder_parse_arp(struct vder_iface *vif, struct vde_buff *vdb)
{
	struct vde_arp_header *ah;
	struct vder_arp_entry *ae=(struct vder_arp_entry*)malloc(sizeof(struct vder_arp_entry));
	if (!ae)
		return -1;
	ah = arphead(vdb);
	memcpy(ae->macaddr,ah->s_mac,6);
	ae->ipaddr = ah->s_addr;

	vder_add_arp_entry(vif, ae);

	if(ntohs(ah->opcode) == ARP_REQUEST)
		vder_arp_reply(vif, vdb);
	return 0;
}

struct vder_arp_entry *vder_arp_get_record_by_macaddr(struct vder_iface *vif, uint8_t *mac)
{
	struct rb_node *node;
	struct vder_arp_entry *found=NULL;
	node = vif->arp_table.rb_node;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (memcmp(entry->macaddr, mac, ETHERNET_ADDRESS_SIZE) == 0) {
			found = entry;
			break;
		}
		node = node->rb_left;
	}
	if (found)
		return found;
	node = vif->arp_table.rb_node;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		if (memcmp(entry->macaddr, mac, ETHERNET_ADDRESS_SIZE) == 0) {
			found = entry;
			break;
		}
		node = node->rb_right;
	}
	return found;
}

int vder_arp_get_neighbors(struct vder_iface *vif, uint32_t *neighbors, int vector_size)
{
	int i = 0;
	struct rb_node *node;
	if (vector_size <= 0)
		return -EINVAL;

	node = vif->arp_table.rb_node;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		neighbors[i++] = entry->ipaddr;
		if (i == vector_size)
			return i;
		node = node->rb_left;
	}
	node = vif->arp_table.rb_node;
	if (!node)
		return i;
	node = node->rb_right;
	while(node) {
		struct vder_arp_entry *entry = rb_entry(node, struct vder_arp_entry, rb_node);
		neighbors[i++] = entry->ipaddr;
		if (i == vector_size)
			return i;
		node = node->rb_right;
	}
	return i;
}
