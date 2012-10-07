#ifndef _INCLUDE_PICO_PROTOCOL 
#define _INCLUDE_PICO_PROTOCOL 
RB_HEAD(pico_protocol_tree, pico_protocol);
RB_PROTOTYPE(pico_protocol_tree, pico_protocol, node, pico_dev_cmp);
#define MAX_PROTOCOL_NAME 16
enum pico_layer {
  PICO_LAYER_DATALINK = 2,  /* Ethernet only. */
  PICO_LAYER_NETWORK = 3,   /* IPv4, IPv6, ARP. Arp is there because it communicates with L2 */
  PICO_LAYER_TRANSPORT = 4, /* UDP, TCP, DHCP, ICMP */
  PICO_LAYER_SOCKET = 5     /* Socket management */
};


struct pico_protocol {
  char name[MAX_PROTOCOL_NAME];
  uint32_t hash;
  enum pico_layer layer;
  struct pico_queue *qin;
  struct pico_queue *qout;
  struct pico_frame *(*alloc)(struct pico_protocol *self, int size); /* Frame allocation. */
  int (*encap)(struct pico_protocol *self, struct pico_frame *p); /* Send function. */
  int (*decap)(struct pico_protocol *self, struct pico_frame *p); /* Recv function  */
  RB_ENTRY(pico_protocol) node;
};





#endif
