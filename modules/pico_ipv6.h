/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_IPV6
#define _INCLUDE_PICO_IPV6
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol pico_proto_ipv6;
extern const uint8_t PICO_IPV6_ANY[PICO_SIZE_IP6];


/* This module is responsible for routing outgoing packets and 
 * delivering incoming packets to other layers
 */

/* Interface for processing incoming ipv6 packets (decap/deliver) */
int pico_ipv6_process_in(struct pico_frame *f);

/* Interface for processing outgoing ipv6 frames (encap/push) */
int pico_ipv6_process_out(struct pico_frame *f);

/* Return estimated overhead for ipv6 frames to define allocation */
int pico_ipv6_overhead(struct pico_frame *f);

#endif
