#ifndef _INCLUDE_PICO_ARP
#define _INCLUDE_PICO_ARP
#include "rb.h"
#include "pico_eth.h"

int pico_arp_receive(struct pico_frame *);

struct pico_arp *pico_arp_get(struct pico_frame *);
struct pico_arp *pico_arp_get_gateway(struct pico_ip4 gw);

int pico_arp_query(struct pico_frame *);

#define PICO_ARP_STATUS_REACHABLE 0x00
#define PICO_ARP_STATUS_PERMANENT 0x01
#define PICO_ARP_STATUS_STALE     0x02

/* Arp Entries for the tables. */
struct pico_arp {
/* CAREFUL MAN! ARP entry MUST begin with a pico_eth structure, 
 * due to in-place casting!!! */
  struct pico_eth eth;
  struct pico_ip4 ipv4;
  int    arp_status;
  uint32_t timestamp;
  RB_ENTRY(pico_arp) node;
};
#endif
