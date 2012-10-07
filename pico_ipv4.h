#ifndef _INCLUDE_PICO_IPV4
#define _INCLUDE_PICO_IPV4
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol *pico_proto_ipv4;


/* This module is responsible for routing outgoing packets and 
 * delivering incoming packets to other layers
 */

/* Interface for processing incoming ipv4 packets (decap/deliver) */
int pico_ipv4_process_in(struct pico_frame *f);

/* Interface for processing outgoing ipv4 frames (encap/push) */
int pico_ipv4_process_out(struct pico_frame *f);

/* Return estimated overhead for ipv4 frames to define allocation */
int pico_ipv4_overhead(struct pico_frame *f);

#endif
