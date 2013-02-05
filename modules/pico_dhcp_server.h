/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_SERVER
#define _INCLUDE_PICO_DHCP_SERVER

#include "pico_dhcp_common.h"

#ifdef PICO_SUPPORT_DHCPD

struct pico_dhcpd_settings
{
	struct pico_device *dev;
	uint32_t my_ip;//unused atm
	uint32_t netmask; //unused atm
	uint32_t pool_start;
	uint32_t pool_next;
	uint32_t pool_end;
	uint32_t lease_time;
	uint8_t flags;//unused atm
};

#define FLAG_BROADCAST (htons(0xF000))


enum dhcp_negotiation_state {
	DHCPSTATE_DISCOVER = 0,
	DHCPSTATE_OFFER,
	DHCPSTATE_REQUEST,
	DHCPSTATE_ACK
};

struct pico_dhcp_negotiation {
	struct pico_dhcp_negotiation *next;
	uint32_t xid;
	uint8_t hwaddr[6];
	uint32_t assigned_address;
	enum dhcp_negotiation_state state;
	struct pico_arp *arp;
};

void pico_dhcp_server_loop(struct pico_device* device);

//TODO remove this workaround (depending on how much we use the state we could pull the enum into the common.h
#define DHCPSTATE_DISCOVER 0

// configuration info : 
#define SERVER_ADDR long_be(0x0a280001)
#define NETMASK long_be(0xffffff00)
#define BROADCAST long_be(0x0a2800ff)
#define OPENDNS (long_be(0xd043dede))
#define POOL_START long_be(0x0a280064)
#define POOL_END long_be(0x0a2800ff)
#define LEASE_TIME long_be(0x00000078)

#endif
#endif
