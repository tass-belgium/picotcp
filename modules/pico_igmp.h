/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Kristof Roelants, Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#ifndef _INCLUDE_PICO_IGMP
#define _INCLUDE_PICO_IGMP

#define PICO_IGMPV1 1
#define PICO_IGMPV2 2
#define PICO_IGMPV3 3

extern struct pico_protocol pico_proto_igmp;

int pico_igmp_join_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link);
int pico_igmp_leave_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link);
#endif /* _INCLUDE_PICO_IGMP */
