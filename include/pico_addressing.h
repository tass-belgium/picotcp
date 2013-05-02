/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_ADDRESSING
#define _INCLUDE_PICO_ADDRESSING
#include <stdint.h>


struct pico_ip4
{
  uint32_t addr;
};
#define PICO_SIZE_IP4 4


struct pico_ip6
{
  uint8_t addr[16];
};
#define PICO_SIZE_IP6 16

struct pico_eth
{
  uint8_t addr[6];
  uint8_t padding[2];
};
#define PICO_SIZE_ETH 6

extern const uint8_t PICO_ETHADDR_ALL[];


struct pico_trans
{
  uint16_t sport;
  uint16_t dport;

};
#define PICO_SIZE_TRANS 8


/* Here are some protocols. */
#define PICO_PROTO_IPV4   0
#define PICO_PROTO_ICMP4  1
#define PICO_PROTO_IGMP  2
#define PICO_PROTO_TCP    6
#define PICO_PROTO_UDP    17
#define PICO_PROTO_IPV6   41
#define PICO_PROTO_ICMP6  58

#endif
