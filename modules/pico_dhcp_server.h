/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_SERVER
#define _INCLUDE_PICO_DHCP_SERVER

#include "pico_dhcp_common.h"
#include "pico_addressing.h"

struct pico_dhcp_server_setting
{
  uint32_t pool_start;
  uint32_t pool_next;
  uint32_t pool_end;
  uint32_t lease_time;
  struct pico_device *dev;
  struct pico_socket *s;
  struct pico_ip4 server_ip;
  struct pico_ip4 netmask;
  uint8_t flags; /* unused atm */
};

/* required field: IP address of the interface to serve, only IPs of this network will be served. */
int pico_dhcp_server_initiate(struct pico_dhcp_server_setting *dhcps);

#endif /* _INCLUDE_PICO_DHCP_SERVER */
