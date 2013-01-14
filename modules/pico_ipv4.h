/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

*********************************************************************/
#ifndef _INCLUDE_PICO_IPV4
#define _INCLUDE_PICO_IPV4
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol pico_proto_ipv4;


struct __attribute__((packed)) pico_ipv4_hdr {
  uint8_t vhl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t proto;
  uint16_t crc;
  struct pico_ip4 src;
  struct pico_ip4 dst;
};

/* Interface: link to device */
struct pico_mcast_list;

struct pico_ipv4_link
{
  struct pico_device *dev;
  struct pico_ip4 address;
  struct pico_ip4 netmask;
  struct pico_mcast_list *mcast_head;
  RB_ENTRY(pico_ipv4_link) node;
};

#define PICO_SIZE_IP4HDR ((sizeof(struct pico_ipv4_hdr)))
#define PICO_IPV4_DONTFRAG 0x4000
#define PICO_IPV4_DEFAULT_TTL 64

int pico_ipv4_to_string(char *ipbuf, const uint32_t ip);
int pico_string_to_ipv4(const char *ipstr, uint32_t *ip);
int pico_ipv4_valid_netmask(uint32_t mask);
int pico_ipv4_is_unicast(uint32_t address); 
int pico_ipv4_is_broadcast(uint32_t addr);

void pico_proto_ipv4_init(void);
int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask);
int pico_ipv4_link_del(struct pico_device *dev, struct pico_ip4 address);
int pico_ipv4_rebound(struct pico_frame *f);
int pico_ipv4_frame_push(struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto);
struct pico_ipv4_link *pico_ipv4_link_get(struct pico_ip4 *address);
struct pico_device *pico_ipv4_link_find(struct pico_ip4 *address);
struct pico_ip4 *pico_ipv4_source_find(struct pico_ip4 *dst);
int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link);
int pico_ipv4_route_del(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link);
struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_ip4 *addr);
void pico_ipv4_unreachable(struct pico_frame *f, int err);

#endif
