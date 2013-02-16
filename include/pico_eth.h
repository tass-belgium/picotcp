/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_ETH
#define _INCLUDE_PICO_ETH
#include "pico_addressing.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"


struct __attribute__((packed)) pico_eth_hdr {
  uint8_t   daddr[6];
  uint8_t   saddr[6];
  uint16_t  proto;
};

#define PICO_SIZE_ETHHDR 14

#endif
