/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_ADDRESSING
#define INCLUDE_PICO_ADDRESSING

#include "pico_config.h"
#include "pico_constants.h"

#define IEEE802154_AM_NONE      (0u)
#define IEEE802154_AM_RES       (1u)
#define IEEE802154_AM_SHORT     (2u)
#define IEEE802154_AM_EXTENDED  (3u)

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

PACKED_STRUCT_DEF pico_ieee802154_addr_short
{
    uint16_t addr;
};

PACKED_STRUCT_DEF pico_ieee802154_addr_ext
{
    uint8_t addr[8];
};

union pico_ieee802154_addr_u {
    struct pico_ieee802154_addr_short _short;
    struct pico_ieee802154_addr_ext   _ext;
};

// ADDRESS MODE DEFINITIONS (IEEE802.15.4)
struct pico_ieee802154_addr
{
    union pico_ieee802154_addr_u addr;
    uint8_t mode;
    uint8_t padding;
};
#define PICO_IEEE802154_AM_SIZE(mode) (IEEE802154_AM_EXTENDED == (mode) ?      \
                                       (PICO_SIZE_IEEE802154_EXT) :            \
                                       (IEEE802154_AM_SHORT == (mode) ?        \
                                        (PICO_SIZE_IEEE802154_SHORT) :         \
                                        (0u)                                   \
                                       )                                       \
                                      )

#define PICO_IEEE802154_SIZE(addr) (PICO_IEEE802154_AM_SIZE((addr)->mode))


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
