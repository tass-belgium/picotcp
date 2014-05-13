/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_STACK
#define INCLUDE_PICO_STACK
#include "pico_config.h"
#include "pico_frame.h"

#define PICO_MAX_TIMERS 20

#define PICO_ETH_MTU 1514
#define PICO_IP_MTU 1500u

/* ===== RECEIVING FUNCTIONS (from dev up to socket) ===== */

/* TRANSPORT LEVEL */
/* interface towards network */
int32_t pico_transport_receive(struct pico_frame *f, uint8_t proto);

/* NETWORK LEVEL */
/* interface towards ethernet */
int32_t pico_network_receive(struct pico_frame *f);

/* The pico_ethernet_receive() function is used by
 * those devices supporting ETH in order to push packets up
 * into the stack.
 */
/* DATALINK LEVEL */
int32_t pico_ethernet_receive(struct pico_frame *f);

/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 * The zerocopy version will associate the current buffer to the newly created frame.
 * Warning: the buffer used in the zerocopy version MUST have been allocated using PICO_ZALLOC()
 */
int32_t pico_stack_recv(struct pico_device *dev, uint8_t *buffer, uint32_t len);
int32_t pico_stack_recv_zerocopy(struct pico_device *dev, uint8_t *buffer, uint32_t len);
int32_t pico_stack_recv_zerocopy_ext_buffer(struct pico_device *dev, uint8_t *buffer, uint32_t len);

/* ===== SENDIING FUNCTIONS (from socket down to dev) ===== */

int32_t pico_network_send(struct pico_frame *f);
int32_t pico_ethernet_send(struct pico_frame *f);
int32_t pico_sendto_dev(struct pico_frame *f);

/* ----- Initialization ----- */
int pico_stack_init(void);

/* ----- Loop Function. ----- */
void pico_stack_tick(void);
void pico_stack_loop(void);

/* ---- Notifications for stack errors */
int pico_notify_socket_unreachable(struct pico_frame *f);
int pico_notify_proto_unreachable(struct pico_frame *f);
int pico_notify_dest_unreachable(struct pico_frame *f);
int pico_notify_ttl_expired(struct pico_frame *f);

/* Various. */
struct pico_timer;
int pico_source_is_local(struct pico_frame *f);
void pico_store_network_origin(void *src, struct pico_frame *f);
struct pico_timer *pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg);
void pico_timer_cancel(struct pico_timer *t);
pico_time pico_timer_get_expire(struct pico_timer *t);
uint32_t pico_rand(void);
void pico_rand_feed(uint32_t feed);
void pico_to_lowercase(char *str);
int pico_address_compare(union pico_address *a, union pico_address *b, uint16_t proto);

#endif
