/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_PROTOCOL 
#define _INCLUDE_PICO_PROTOCOL 
#include <stdint.h>
#include "pico_queue.h"

#define PICO_LOOP_DIR_IN   1
#define PICO_LOOP_DIR_OUT  2

enum pico_layer {
  PICO_LAYER_DATALINK = 2,  /* Ethernet only. */
  PICO_LAYER_NETWORK = 3,   /* IPv4, IPv6, ARP. Arp is there because it communicates with L2 */
  PICO_LAYER_TRANSPORT = 4, /* UDP, TCP, ICMP */
  PICO_LAYER_SOCKET = 5     /* Socket management */
};

enum pico_err_e {
  PICO_ERR_NOERR = 0,
  PICO_ERR_EPERM,
  PICO_ERR_ENOENT,
  /* ... */
  PICO_ERR_EINTR = 4,
  PICO_ERR_EIO,
  PICO_ERR_ENXIO, 
  /* ... */
  PICO_ERR_EAGAIN = 11,
  PICO_ERR_ENOMEM,
  PICO_ERR_EACCESS,
  PICO_ERR_EFAULT,
  /* ... */
  PICO_ERR_EBUSY = 16,
  PICO_ERR_EEXIST = 17,
  /* ... */
  PICO_ERR_EINVAL = 22,
  /* ... */
  PICO_ERR_EPROTO = 71,
  PICO_ERR_ENOPROTOOPT = 92,
  PICO_ERR_EPROTONOSUPPORT = 93,

  /* ... */
  PICO_ERR_EADDRINUSE = 98,
  PICO_ERR_EADDRNOTAVAIL,
  PICO_ERR_ENETUNREACH,

  /* ... */
  PICO_ERR_ECONNRESET = 104,

  /* ... */
  PICO_ERR_EISCONN = 106,
  PICO_ERR_ENOTCONN,
  PICO_ERR_ESHUTDOWN,
  /* ... */
  PICO_ERR_ETIMEDOUT = 110,
  PICO_ERR_ECONNREFUSED = 111,
  PICO_ERR_EHOSTDOWN,
  PICO_ERR_EHOSTUNREACH,
  /* ... */
  PICO_ERR_EOPNOTSUPP = 122,

};

typedef enum pico_err_e pico_err_t;
extern volatile pico_err_t pico_err;

#define IS_IPV6(f) ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x60)
#define IS_IPV4(f) ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x40)

#define MAX_PROTOCOL_NAME 16

struct pico_protocol {
  char name[MAX_PROTOCOL_NAME];
  uint32_t hash;
  enum pico_layer layer;
  int proto_number;
  struct pico_queue *q_in;
  struct pico_queue *q_out;
  struct pico_frame *(*alloc)(struct pico_protocol *self, int size); /* Frame allocation. */
  int (*push) (struct pico_protocol *self, struct pico_frame *p);    /* Push function, for active outgoing pkts from above */
  int (*process_out)(struct pico_protocol *self, struct pico_frame *p); /* Send loop. */
  int (*process_in)(struct pico_protocol *self, struct pico_frame *p); /* Recv loop. */
};

int pico_protocols_loop(int loop_score);
void pico_protocol_init(struct pico_protocol *p);

int pico_protocol_datalink_loop(int loop_score, int direction);
int pico_protocol_network_loop(int loop_score, int direction);
int pico_protocol_transport_loop(int loop_score, int direction);
int pico_protocol_socket_loop(int loop_score, int direction);

#endif
