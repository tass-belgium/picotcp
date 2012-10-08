#ifndef _INCLUDE_PICO_ARP
#define _INCLUDE_PICO_ARP
#include "rb.h"
#include "pico_eth.h"

int pico_arp_receive(struct pico_frame *);

struct pico_arp4 *pico_arp4_get(struct pico_frame *);
struct pico_arp6 *pico_arp6_get(struct pico_frame *);

int pico_arp4_query(struct pico_frame *);
int pico_arp6_query(struct pico_frame *);

#define PICO_ARP_STATUS_REACHABLE 0x00
#define PICO_ARP_STATUS_PERMANENT 0x01
#define PICO_ARP_STATUS_STALE     0x02

/* Arp Entries for the tables. */
struct pico_arp4 {
/* CAREFUL MAN! ARP entry MUST begin with a pico_eth structure, 
 * due to in-place casting!!! */
  struct pico_eth eth;
  struct pico_ip4 ipv4;
  int    arp_status;
  RB_ENTRY(pico_arp4) node;
};

struct pico_arp6 {
/* CAREFUL MAN! ARP entry MUST begin with a pico_eth structure, 
 * due to in-place casting!!! */
  struct pico_eth eth;
  struct pico_ip6 ipv6;
  int    arp_status;
  RB_ENTRY(pico_arp6) node;
};


#endif
