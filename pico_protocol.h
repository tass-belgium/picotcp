#ifndef _INCLUDE_PICO_PROTOCOL 
#define _INCLUDE_PICO_PROTOCOL 
enum pico_layer {
  PICO_LAYER_DATALINK = 2,  /* Ethernet only. */
  PICO_LAYER_NETWORK = 3,   /* IPv4, IPv6, ARP. Arp is there because it communicates with L2 */
  PICO_LAYER_TRANSPORT = 4, /* UDP, TCP, DHCP, ICMP */
  PICO_LAYER_SOCKET = 5     /* Socket management */
};


struct pico_protocol {
  enum pico_layer layer;
  struct pico_queue *q_in;
  struct pico_queue *q_out;
  struct pico_frame *(*alloc)(struct pico_protocol *self, int size); /* Frame allocation. */
  int (*process_out)(struct pico_protocol *self, struct pico_frame *p); /* Send function. */
  int (*process_in)(struct pico_protocol *self, struct pico_frame *p); /* Recv function. */
 // RB_ENTRY(pico_protocol) node;
};

#endif
