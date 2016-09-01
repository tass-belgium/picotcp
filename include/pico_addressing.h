/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_ADDRESSING
#define INCLUDE_PICO_ADDRESSING

#include "pico_config.h"
#include "pico_constants.h"

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

extern const uint8_t PICO_ETHADDR_ALL[];

enum pico_ll_mode
{
    LL_MODE_ETHERNET = 0,
    LL_MODE_6LOWPAN,
};

/******************************************************************************
 *  IEE802.15.4 Address Definitions
 ******************************************************************************/

/* IEE802.15.4 supports 16-bit short addresses */
PACKED_STRUCT_DEF pico_802154_short
{
    uint16_t addr;
};

/* And also EUI-64 addresses */
PACKED_STRUCT_DEF pico_802154_ext
{
    uint8_t addr[8];
};

/* Address memory as either a short 16-bit address or a 64-bit address */
union pico_802154_u
{
    uint8_t data[8];
    struct pico_802154_short _short;
    struct pico_802154_ext _ext;
};

/* Storage data structure for IEEE802.15.4 addresses */
struct pico_802154
{
    union pico_802154_u addr;
    uint8_t mode;
};

/* Info data structure to pass to pico_device_init by the device driver */
struct pico_802154_info
{
    struct pico_802154_short addr_short;
    struct pico_802154_ext addr_ext;
    struct pico_802154_short pan_id;
};

/* Different addressing modes for IEEE802.15.4 addresses */
#define AM_802154_NONE      (0u)
#define AM_802154_RES       (1u)
#define AM_802154_SHORT     (2u)
#define AM_802154_EXT       (3u)

#define SIZE_802154_SHORT   (2u)
#define SIZE_802154_EXT     (8u)

#define SIZE_802154(m) (((m) == 2) ? (2) : (((m) == 3) ? (8) : (0)))

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
