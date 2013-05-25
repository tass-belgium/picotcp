/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_IPV4
#define _INCLUDE_PICO_IPV4
#include "pico_addressing.h"
#include "pico_protocol.h"
#include "pico_tree.h"

#define PICO_IPV4_INADDR_ANY 0x00000000U

#define PICO_SIZE_IP4HDR ((sizeof(struct pico_ipv4_hdr)))
#define PICO_IPV4_DONTFRAG 0x4000
#define PICO_IPV4_MOREFRAG 0x2000
#define PICO_IPV4_FRAG_MASK 0x1FFF
#define PICO_IPV4_DEFAULT_TTL 64

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
  uint8_t options[0];
};

struct __attribute__((packed)) pico_ipv4_pseudo_hdr
{
  struct pico_ip4 src;
  struct pico_ip4 dst;
  uint8_t zeros;
  uint8_t proto;
  uint16_t len;
};

/* Interface: link to device */
struct pico_mcast_list;

struct pico_ipv4_link
{
  struct pico_device *dev;
  struct pico_ip4 address;
  struct pico_ip4 netmask;
#ifdef PICO_SUPPORT_MCAST
  struct pico_tree *MCASTGroups;
  uint8_t mcast_compatibility;
  uint8_t mcast_last_query_interval;
#endif
};

#ifdef PICO_SUPPORT_MCAST
struct pico_mcast_group {
  uint8_t filter_mode;
  uint16_t reference_count;
  struct pico_ip4 mcast_addr;
  struct pico_tree MCASTSources;
};
#endif

int pico_ipv4_to_string(char *ipbuf, const uint32_t ip);
int pico_string_to_ipv4(const char *ipstr, uint32_t *ip);
int pico_ipv4_valid_netmask(uint32_t mask);
int pico_ipv4_is_unicast(uint32_t address); 
int pico_ipv4_is_multicast(uint32_t address); 
int pico_ipv4_is_broadcast(uint32_t addr);

int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask);
int pico_ipv4_link_del(struct pico_device *dev, struct pico_ip4 address);
int pico_ipv4_rebound(struct pico_frame *f);

int pico_ipv4_frame_push(struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto);
struct pico_ipv4_link *pico_ipv4_link_get(struct pico_ip4 *address);
struct pico_ipv4_link *pico_ipv4_link_by_dev(struct pico_device *dev);
struct pico_device *pico_ipv4_link_find(struct pico_ip4 *address);
struct pico_ip4 *pico_ipv4_source_find(struct pico_ip4 *dst);
int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link);
int pico_ipv4_route_del(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link);
struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_ip4 *addr);
void pico_ipv4_unreachable(struct pico_frame *f, int err);

int pico_ipv4_mcast_join(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter);
int pico_ipv4_mcast_leave(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter);
struct pico_ipv4_link *pico_ipv4_get_default_mcastlink(void);

#endif /* _INCLUDE_PICO_IPV4 */
