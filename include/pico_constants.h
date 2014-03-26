/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_CONST
#define INCLUDE_PICO_CONST
/* Included from pico_config.h */

/** Non-endian dependant constants */
#define PICO_SIZE_IP4    4
#define PICO_SIZE_IP6   16
#define PICO_SIZE_ETH    6
#define PICO_SIZE_TRANS  8

/** Endian-dependant constants **/
typedef uint64_t pico_time;
extern volatile uint64_t pico_tick;

#ifdef PICO_BIGENDIAN

# define PICO_IDETH_IPV4 0x0800
# define PICO_IDETH_ARP 0x0806
# define PICO_IDETH_IPV6 0x86DD

# define PICO_ARP_REQUEST 0x0001
# define PICO_ARP_REPLY   0x0002
# define PICO_ARP_HTYPE_ETH 0x0001

#define short_be(x) (x)
#define long_be(x) (x)
#define long_long_be(x) (x)

static inline uint16_t short_from(void *_p)
{
    unsigned char *p = (unsigned char *)_p;
    uint16_t r, p0, p1;
    p0 = p[0];
    p1 = p[1];
    r = (p0 << 8) + p1;
    return r;
}

static inline uint32_t long_from(void *_p)
{
    unsigned char *p = (unsigned char *)_p;
    uint32_t r, p0, p1, p2, p3;
    p0 = p[0];
    p1 = p[1];
    p2 = p[2];
    p3 = p[3];
    r = (p0 << 24) + (p1 << 16) + (p2 << 8) + p3;
    return r;
}

#else

static inline uint16_t short_from(void *_p)
{
    unsigned char *p = (unsigned char *)_p;
    uint16_t r, _p0, _p1;
    _p0 = p[0];
    _p1 = p[1];
    r = (uint16_t)((_p1 << 8u) + _p0);
    return r;
}

static inline uint32_t long_from(void *_p)
{
    unsigned char *p = (unsigned char *)_p;
    uint32_t r, _p0, _p1, _p2, _p3;
    _p0 = p[0];
    _p1 = p[1];
    _p2 = p[2];
    _p3 = p[3];
    r = (_p3 << 24) + (_p2 << 16) + (_p1 << 8) + _p0;
    return r;
}


# define PICO_IDETH_IPV4 0x0008
# define PICO_IDETH_ARP 0x0608
# define PICO_IDETH_IPV6 0xDD86

# define PICO_ARP_REQUEST 0x0100
# define PICO_ARP_REPLY   0x0200
# define PICO_ARP_HTYPE_ETH 0x0100

static inline uint16_t short_be(uint16_t le)
{
    return (uint16_t)(((le & 0xFFu) << 8) | ((le >> 8u) & 0xFFu));
}

static inline uint32_t long_be(uint32_t le)
{
    uint8_t *b = (uint8_t *)&le;
    uint32_t be = 0;
    uint32_t b0, b1, b2;
    b0 = b[0];
    b1 = b[1];
    b2 = b[2];
    be = b[3] + (b2 << 8) + (b1 << 16) + (b0 << 24);
    return be;
}
static inline uint64_t long_long_be(uint64_t le)
{
    uint8_t *b = (uint8_t *)&le;
    uint64_t be = 0;
    uint64_t b0, b1, b2, b3, b4, b5, b6;
    b0 = b[0];
    b1 = b[1];
    b2 = b[2];
    b3 = b[3];
    b4 = b[4];
    b5 = b[5];
    b6 = b[6];
    be = b[7] + (b6 << 8) + (b5 << 16) + (b4 << 24) + (b3 << 32) + (b2 << 40) + (b1 << 48) + (b0 << 56);
    return be;
}
#endif

/*** *** *** *** *** *** ***
 ***     ARP CONFIG      ***
 *** *** *** *** *** *** ***/

#include "pico_addressing.h"

/* Maximum amount of accepted ARP requests per burst interval */
#define PICO_ARP_MAX_RATE 1
/* Duration of the burst interval in milliseconds */
#define PICO_ARP_INTERVAL 1000

/* Add well-known host numbers here. (bigendian constants only beyond this point) */
#define PICO_IP4_ANY (0x00000000U)
#define PICO_IP4_BCAST (0xffffffffU)

/* defined in modules/pico_ipv6.c */
#ifdef PICO_SUPPORT_IPV6
extern const uint8_t PICO_IPV6_ANY[PICO_SIZE_IP6];
#endif

static inline uint32_t pico_hash(const void *buf, uint32_t size)
{
    uint32_t hash = 5381;
    uint32_t i;
    const uint8_t *ptr = (const uint8_t *)buf;
    for(i = 0; i < size; i++)
        hash = ((hash << 5) + hash) + ptr[i]; /* hash * 33 + char */
    return hash;
}

/* Debug */
/* #define PICO_SUPPORT_DEBUG_MEMORY */
/* #define PICO_SUPPORT_DEBUG_TOOLS */
#endif
