/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_ADDRESSING
#define INCLUDE_PICO_ADDRESSING

#include "pico_config.h"

PACKED_STRUCT_DEF pico_ip4
{
    uint32_t addr;
};

PACKED_STRUCT_DEF pico_ip6
{
    uint8_t addr[16];
};

union pico_address
{
    struct pico_ip4 ip4;
    struct pico_ip6 ip6;
};

PACKED_STRUCT_DEF pico_eth
{
    uint8_t addr[6];
    uint8_t padding[2];
};

enum pico_ll_mode {
    LL_MODE_ETHERNET = 0,
    LL_MODE_SIXLOWPAN
};

#ifdef PICO_SUPPORT_SIXLOWPAN
PACKED_STRUCT_DEF pico_sixlowpan_addr_short
{
    uint16_t addr;
};

PACKED_STRUCT_DEF pico_sixlowpan_addr_ext
{
    uint8_t addr[8];
};

/**
 *  ADDRESS MODE DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_ADDRESS_MODE_NONE = 0,
    IEEE802154_ADDRESS_MODE_RES,
    IEEE802154_ADDRESS_MODE_SHORT,
    IEEE802154_ADDRESS_MODE_EXTENDED,
    IEEE802154_ADDRESS_MODE_BOTH
} __attribute__((packed)) IEEE802154_address_mode_t;

struct pico_sixlowpan_addr
{
    struct pico_sixlowpan_addr_short _short;
    struct pico_sixlowpan_addr_ext _ext;
    IEEE802154_address_mode_t _mode;
};
#endif

extern const uint8_t PICO_ETHADDR_ALL[];


PACKED_STRUCT_DEF pico_trans
{
    uint16_t sport;
    uint16_t dport;

};

/* Here are some protocols. */
#define PICO_PROTO_IPV4   0
#define PICO_PROTO_ICMP4  1
#define PICO_PROTO_IGMP  2
#define PICO_PROTO_TCP    6
#define PICO_PROTO_UDP    17
#define PICO_PROTO_IPV6   41
#define PICO_PROTO_ICMP6  58

#endif
