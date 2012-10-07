#ifndef _INCLUDE_PICO_ETH
#define _INCLUDE_PICO_ETH
#include "pico_addressing.h"

#define PICO_ARP_STATUS_REACHABLE 0x00
#define PICO_ARP_STATUS_PERMANENT 0x01
#define PICO_ARP_STATUS_STALE     0x02

struct pico_arp4 {
  struct pico_eth eth;
  struct pico_ipv4 ipv4;
  int    arp_status;
  RB_ENTRY(pico_arp_entry) node;
};

struct pico_arp6 {
  struct pico_eth eth;
  struct pico_ipv6 ipv6;
  int    arp_status;
  RB_ENTRY(pico_arp_entry) node;
};

/* Interface for processing incoming eth frames (decap/route) */
int pico_eth_process_in(struct pico_frame *f);

/* Interface for processing outgoing eth frames (encap/push) */
int pico_eth_process_out(struct pico_frame *f);

/* Return estimated overhead for eth frames to define allocation */
int pico_eth_overhead(struct pico_frame *f);

#endif
