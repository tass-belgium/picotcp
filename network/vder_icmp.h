/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef __VDER_ICMP
#define __VDER_ICMP
int vder_icmp_service_unreachable(uint32_t dst, uint8_t *foot);
int vder_icmp_host_unreachable(uint32_t dst, uint8_t *foot);
int vder_icmp_recv(struct vde_buff *vdb);
int vder_icmp_filter(uint32_t dst, uint8_t *foot);
int vder_icmp_ttl_expired(uint32_t dst, uint8_t *foot);
#endif
