/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_ADDRESSING
#define INCLUDE_PICO_ADDRESSING

#include "pico_config.h"

#define IEEE_AM_NONE 0
#define IEEE_AM_RES 1
#define IEEE_AM_SHORT 2
#define IEEE_AM_EXTENDED 3
#define IEEE_AM_BOTH 4

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

enum pico_ll_mode
{
    LL_MODE_ETHERNET = 0,
    LL_MODE_SIXLOWPAN
};

PACKED_STRUCT_DEF pico_ieee_addr_short
{
    uint16_t addr;
};

PACKED_STRUCT_DEF pico_ieee_addr_ext
{
    uint8_t addr[8];
};

// ADDRESS MODE DEFINITIONS (IEEE802.15.4)
struct pico_ieee_addr
{
    struct pico_ieee_addr_short _short;
    struct pico_ieee_addr_ext _ext;
    uint8_t _mode;
    uint8_t padding;
};

#define pico_ieee_addr_len(am) ((IEEE_AM_BOTH == (int)(am) || IEEE_AM_SHORT == (int)(am)) ? (2u) : \
                                (((IEEE_AM_EXTENDED == (int)(am)) ? (8u) : (0u))))

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
