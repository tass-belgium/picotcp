#ifndef _INCLUDE_PICO_ETH
#define _INCLUDE_PICO_ETH
#include "pico_addressing.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"

#define PICO_ARP_STATUS_REACHABLE 0x00
#define PICO_ARP_STATUS_PERMANENT 0x01
#define PICO_ARP_STATUS_STALE     0x02

struct pico_arp4 {
  struct pico_eth eth;
  struct pico_ip4 ipv4;
  int    arp_status;
//  RB_ENTRY(pico_arp_entry) node;
};

struct pico_arp6 {
  struct pico_eth eth;
  struct pico_ip6 ipv6;
  int    arp_status;
//  RB_ENTRY(pico_arp_entry) node;
};

struct __attribute__((packed)) pico_eth_hdr {
  uint8_t   daddr[6];
  uint8_t   saddr[6];
  uint16_t  proto;
};

#endif
