/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_SERVER
#define _INCLUDE_PICO_DHCP_SERVER

#include "pico_dhcp_common.h"
#include "pico_addressing.h"


struct pico_dhcpd_settings
{
	struct pico_device *dev;
	struct pico_ip4 my_ip;
	struct pico_ip4 netmask;
	uint32_t pool_start;
	uint32_t pool_next;
	uint32_t pool_end;
	uint32_t lease_time;
	uint8_t flags;//unused atm
};

#define FLAG_BROADCAST (htons(0xF000))


struct pico_dhcp_negotiation {
	struct pico_dhcp_negotiation *next;
	uint32_t xid;
	struct pico_eth eth;
	uint32_t assigned_address;
	enum dhcp_negotiation_state state;
	struct pico_ip4 ipv4;
};

//you pass this function a pointer to pico_dhcpd_settings. The only required field is the device, the others have default values if they are 0.
int pico_dhcp_server_initiate(struct pico_dhcpd_settings* setting);

// configuration info : 
// These are the default values if something is not filled in for the initiate-call.
// Note that this can give weird effects, e.g. if you fill in the server address, but not the pool_start or end, and they don't match. 
#define SERVER_ADDR long_be(0x0a280001)
#define NETMASK long_be(0xffffff00)
#define BROADCAST long_be(0x0a2800ff)
#define OPENDNS (long_be(0xd043dede))
#define POOL_START long_be(0x0a280064)
#define POOL_END long_be(0x0a2800ff)
#define LEASE_TIME long_be(0x00000078)

#endif
