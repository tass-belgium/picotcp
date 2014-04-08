/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

 *********************************************************************/
#ifndef _INCLUDE_PICO_IPV6
#define _INCLUDE_PICO_IPV6
#include "pico_addressing.h"
#include "pico_protocol.h"

#define PICO_SIZE_IP6HDR ((uint32_t)(sizeof(struct pico_ipv6_hdr)))
#define PICO_IPV6_DEFAULT_HOP 64
#define PICO_IPV6_MIN_MTU 1280

extern const uint8_t PICO_IP6_ANY[PICO_SIZE_IP6];
extern struct pico_protocol pico_proto_ipv6;

PACKED_STRUCT_DEF pico_ipv6_hdr {
    uint32_t vtf;
    uint16_t len;
    uint8_t nxthdr;
    uint8_t hop;
    struct pico_ip6 src;
    struct pico_ip6 dst;
    uint8_t extensions[0];
};

PACKED_STRUCT_DEF pico_ipv6_pseudo_hdr
{
    struct pico_ip6 src;
    struct pico_ip6 dst;
    uint32_t len;
    uint8_t zero[3];
    uint8_t nxthdr;
};

struct pico_ipv6_link
{
    struct pico_device *dev;
    struct pico_ip6 address;
    struct pico_ip6 netmask;
    uint8_t istentative : 1;
    uint8_t isduplicate : 1;
};

PACKED_STRUCT_DEF pico_ipv6_exthdr {
    uint8_t nxthdr;

    PACKED_UNION_DEF ipv6_ext_u {
        PEDANTIC_STRUCT_DEF hopbyhop_s {
            uint8_t len;
            uint8_t options[0];
        } hopbyhop;

        PEDANTIC_STRUCT_DEF destopt_s {
            uint8_t len;
            uint8_t options[0];
        } destopt;

        PEDANTIC_STRUCT_DEF routing_s {
            uint8_t len;
            uint8_t routtype;
            uint8_t segleft;
        } routing;

        PEDANTIC_STRUCT_DEF fragm_s {
            uint8_t res;
            uint8_t frm[2];
            uint8_t id[4];
        } fragm;
    } ext;
};

int pico_ipv6_compare(struct pico_ip6 *a, struct pico_ip6 *b);
int pico_string_to_ipv6(const char *ipstr, uint8_t *ip);
int pico_ipv6_to_string(char *ipbuf, const uint8_t ip[PICO_SIZE_IP6]);
int pico_ipv6_is_unicast(struct pico_ip6 *a);
int pico_ipv6_is_multicast(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_global(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_uniquelocal(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_sitelocal(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_linklocal(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_solicited(const uint8_t addr[PICO_SIZE_IP6]);
int pico_ipv6_is_unspecified(const uint8_t addr[PICO_SIZE_IP6]);

int pico_ipv6_frame_push(struct pico_frame *f, struct pico_ip6 *dst, uint8_t proto);
int pico_ipv6_rebound(struct pico_frame *f);
int pico_ipv6_route_add(struct pico_ip6 address, struct pico_ip6 netmask, struct pico_ip6 gateway, int metric, struct pico_ipv6_link *link);
void pico_ipv6_unreachable(struct pico_frame *f, uint8_t code);

int pico_ipv6_link_add(struct pico_device *dev, struct pico_ip6 address, struct pico_ip6 netmask);
int pico_ipv6_link_del(struct pico_device *dev, struct pico_ip6 address);
int pico_ipv6_cleanup_links(struct pico_device *dev);
struct pico_ipv6_link *pico_ipv6_link_istentative(struct pico_ip6 *address);
struct pico_ipv6_link *pico_ipv6_link_get(struct pico_ip6 *address);
struct pico_device *pico_ipv6_link_find(struct pico_ip6 *address);
struct pico_ip6 pico_ipv6_route_get_gateway(struct pico_ip6 *addr);
struct pico_ip6 *pico_ipv6_source_find(const struct pico_ip6 *dst);
struct pico_ipv6_link *pico_ipv6_link_by_dev(struct pico_device *dev);
struct pico_ipv6_link *pico_ipv6_link_by_dev_next(struct pico_device *dev, struct pico_ipv6_link *last);
#endif
