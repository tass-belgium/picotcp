#ifndef _INCLUDE_PICO_STACK
#define _INCLUDE_PICO_STACK
#include "pico_config.h"
#include "pico_frame.h"


/* ===== RECEIVING FUNCTIONS (from dev up to socket) ===== */

/* SOCKET LEVEL */
int pico_socket_receive(struct pico_frame *f);

/* TRANSPORT LEVEL */
/* interface towards network */
int pico_transport_receive(struct pico_frame *f);


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


int pico_sendto_dev(struct pico_frame *f);
int pico_ethernet_send(struct pico_frame *f);

/* ----- Initialization ----- */
void pico_stack_init(void);

/* ----- Loop Function. ----- */
void pico_stack_loop(void);


#endif
