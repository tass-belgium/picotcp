/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_CLIENT
#define _INCLUDE_PICO_DHCP_CLIENT

#ifdef PICO_SUPPORT_DHCPC

#include "pico_dhcp_common.h"
#include "pico_addressing.h"
#include "pico_protocol.h"


void* pico_dhcp_initiate_negotiation(struct pico_device* device, void (*callback)(void* cli, int code));
void pico_dhcp_process_incoming_message(uint8_t* data, int len);
struct pico_ip4 pico_dhcp_get_address(void* cli);
struct pico_ip4 pico_dhcp_get_gateway(void* cli);

/* possible codes for the callback */
#define PICO_DHCP_SUCCESS 0
#define PICO_DHCP_ERROR   1
#define PICO_DHCP_RESET   2

/* DHCP EVENT TYPE 
 * these come after the message types, used for the state machine*/
#define PICO_DHCP_EVENT_T1                   9
#define PICO_DHCP_EVENT_T2                   10
#define PICO_DHCP_EVENT_LEASE                11
#define PICO_DHCP_EVENT_RETRANSMIT           12



//based on the RFC
//TODO start using this ; for now I'll take the VDER-implementation
/*
enum pico_dhcp_negotiation_state {
	INIT,
	SELECTING,
	REQUESTING,
	BOUND,
	RENEWING,
	REBINDING,
	INIT-REBOOT,
	REBOOTING
};*/


#endif
#endif
