/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_SERVER
#define _INCLUDE_PICO_DHCP_SERVER

#include "pico_dhcp_common.h"
#include "pico_addressing.h"

/* default configuration */ 
#define OPENDNS (long_be(0xd043dede)) /* OpenDNS DNS server 208.67.222.222 */
#define POOL_START long_be(0x00000064)
#define POOL_END long_be(0x000000fe)
#define LEASE_TIME long_be(0x00000078)

struct pico_dhcpd_settings
{
  struct pico_device *dev;
  struct pico_socket *s;
  struct pico_ip4 my_ip;
  struct pico_ip4 netmask;
  uint32_t pool_start;
  uint32_t pool_next;
  uint32_t pool_end;
  uint32_t lease_time;
  uint8_t flags; /* unused atm */
};

struct pico_dhcp_negotiation {
  struct pico_dhcpd_settings *settings;
  struct pico_ip4 ipv4;
  struct pico_eth eth;
  enum dhcp_negotiation_state state;
  uint32_t xid;
  uint32_t assigned_address;
};

/* required settings field: IP address of the interface to serve, only IPs of this network will be served. */
int pico_dhcp_server_initiate(struct pico_dhcpd_settings *setting);

#endif /* _INCLUDE_PICO_DHCP_SERVER */
