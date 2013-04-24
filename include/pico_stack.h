/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_STACK
#define _INCLUDE_PICO_STACK
#include "pico_config.h"
#include "pico_frame.h"

#define PICO_MAX_TIMERS 20

/* ===== RECEIVING FUNCTIONS (from dev up to socket) ===== */

/* TRANSPORT LEVEL */
/* interface towards network */
int pico_transport_receive(struct pico_frame *f, uint8_t proto);

/* NETWORK LEVEL */
/* interface towards ethernet */
int pico_network_receive(struct pico_frame *f);

/* The pico_ethernet_receive() function is used by 
 * those devices supporting ETH in order to push packets up 
 * into the stack. 
 */
/* DATALINK LEVEL */
int pico_ethernet_receive(struct pico_frame *f);

/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 */
int pico_stack_recv(struct pico_device *dev, uint8_t *buffer, int len);


/* ===== SENDIING FUNCTIONS (from socket down to dev) ===== */

int pico_transport_send(struct pico_frame *f);
int pico_network_send(struct pico_frame *f);
int pico_ethernet_send(struct pico_frame *f);
int pico_sendto_dev(struct pico_frame *f);

/* ----- Initialization ----- */
void pico_stack_init(void);

/* ----- Loop Function. ----- */
void pico_stack_tick(void);
void pico_stack_loop(void);

/* ---- Notifications for stack errors */
int pico_notify_socket_unreachable(struct pico_frame *f);
int pico_notify_proto_unreachable(struct pico_frame *f);
int pico_notify_dest_unreachable(struct pico_frame *f);
int pico_notify_ttl_expired(struct pico_frame *f);

/* Various. */
int pico_source_is_local(struct pico_frame *f);
int pico_destination_is_local(struct pico_frame *f);
void pico_store_network_origin(void *src, struct pico_frame *f);
void pico_timer_add(unsigned long expire, void (*timer)(unsigned long, void *), void *arg);
uint32_t pico_rand(void);
void pico_rand_feed(uint32_t feed);

#endif
