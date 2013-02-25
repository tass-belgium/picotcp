/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Simon Maes
*********************************************************************/
#ifndef _INCLUDE_PICO_IPFILTER
#define _INCLUDE_PICO_IPFILTER

#include "pico_device.h"

enum filter_action {
  filter_accept = 0,
  filter_priority,
  filter_reject,
  filter_drop,
};

uint8_t pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto, uint32_t src_addr, uint32_t saddr_netmask, uint32_t dst_addr, uint32_t daddr_netmask, uint8_t sport, uint8_t dport, uint8_t priority, uint8_t tos, enum filter_action action);
int pico_ipv4_filter_del(uint8_t filter_id);
int ipfilter(struct pico_frame *f);

#endif /* _INCLUDE_PICO_IPFILTER */

