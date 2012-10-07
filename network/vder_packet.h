/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef _VDER_PACKET
#define _VDER_PACKET



#define DEFAULT_TTL 64
uint16_t pico_ip_checksum(struct iphdr *iph);
void pico_packet_recv(struct pico_iface *vif, int timeout);
int pico_packet_send(struct vde_buff *vdb, uint32_t dst_ip, uint8_t protocol);
int pico_packet_broadcast(struct vde_buff *vdb, struct pico_iface *iface, uint32_t dst_ip, uint8_t protocol);
char *pico_ntoa(uint32_t addr);

#endif
