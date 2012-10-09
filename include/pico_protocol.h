#ifndef _INCLUDE_PICO_PROTOCOL 
#define _INCLUDE_PICO_PROTOCOL 
#include <stdint.h>
#include "pico_queue.h"
#include "rb.h"


enum pico_layer {
  PICO_LAYER_DATALINK = 2,  /* Ethernet only. */
  PICO_LAYER_NETWORK = 3,   /* IPv4, IPv6, ARP. Arp is there because it communicates with L2 */
  PICO_LAYER_TRANSPORT = 4, /* UDP, TCP, DHCP, ICMP */
  PICO_LAYER_SOCKET = 5     /* Socket management */
};



#define IS_IPV6(f) ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x60)
#define IS_IPV4(f) ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x40)

#define MAX_PROTOCOL_NAME 16

struct pico_protocol {
  char name[MAX_PROTOCOL_NAME];
  uint32_t hash;
  enum pico_layer layer;
  struct pico_queue *q_in;
  struct pico_queue *q_out;
  struct pico_frame *(*alloc)(struct pico_protocol *self, int size); /* Frame allocation. */
  int (*process_out)(struct pico_protocol *self, struct pico_frame *p); /* Send function. */
  int (*process_in)(struct pico_protocol *self, struct pico_frame *p); /* Recv function. */
  RB_ENTRY(pico_protocol) node;
};

#endif
