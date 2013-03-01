/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Simon Maes
*********************************************************************/
#ifndef _INCLUDE_PICO_IPFILTER
#define _INCLUDE_PICO_IPFILTER

#include "pico_device.h"

enum filter_action {
  FILTER_ACCEPT = 0,
  FILTER_PRIORITY,
  FILTER_REJECT,
  FILTER_DROP,
};



int pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto,
  struct pico_ip4 *out_addr, struct pico_ip4 *out_addr_netmask, struct pico_ip4 *in_addr,
  struct pico_ip4 *in_addr_netmask, uint16_t out_port, uint16_t in_port,
  int8_t priority, uint8_t tos, enum filter_action action);

int pico_ipv4_filter_del(uint8_t filter_id);

int ipfilter(struct pico_frame *f);

#endif /* _INCLUDE_PICO_IPFILTER */

