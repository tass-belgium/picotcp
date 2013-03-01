/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_ARP
#define _INCLUDE_PICO_ARP
#include "pico_eth.h"
#include "pico_device.h"

int pico_arp_receive(struct pico_frame *);


struct pico_eth *pico_arp_get(struct pico_frame *f);
int pico_arp_query(struct pico_device *dev, struct pico_ip4 *dst);

#define PICO_ARP_STATUS_REACHABLE 0x00
#define PICO_ARP_STATUS_PERMANENT 0x01
#define PICO_ARP_STATUS_STALE     0x02


struct pico_eth *pico_arp_lookup(struct pico_ip4 *dst);
struct pico_ip4 *pico_arp_reverse_lookup(struct pico_eth *dst);
int pico_arp_create_entry(uint8_t* hwaddr, struct pico_ip4 ipv4, struct pico_device* dev);
#endif
