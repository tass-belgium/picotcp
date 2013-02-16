/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_CONST
#define _INCLUDE_PICO_CONST
/* Included from pico_config.h */
/** Endian-dependant constants **/

extern volatile unsigned long pico_tick;

#ifdef PICO_BIGENDIAN

# define PICO_IDETH_IPV4 0x0800
# define PICO_IDETH_ARP 0x0806
# define PICO_IDETH_IPV6 0x86DD

# define PICO_ARP_REQUEST 0x0001
# define PICO_ARP_REPLY   0x0002
# define PICO_ARP_HTYPE_ETH 0x0001

#define short_be(x) (x)
#define long_be(x) (x)

#else

# define PICO_IDETH_IPV4 0x0008
# define PICO_IDETH_ARP 0x0608
# define PICO_IDETH_IPV6 0xDD86

# define PICO_ARP_REQUEST 0x0100
# define PICO_ARP_REPLY   0x0200
# define PICO_ARP_HTYPE_ETH 0x0100

static inline uint16_t short_be(uint16_t le)
{
  return ((le & 0xFF) << 8) | ((le >> 8) & 0xFF);
}

static inline uint32_t long_be(uint32_t le)
{
  uint8_t *b = (uint8_t *)&le;
  uint32_t be = 0;
  be = b[3] + (b[2] << 8) + (b[1] << 16) + (b[0] << 24);
  return be;
}
#endif


/* Add well-known host numbers here. (bigendian constants only beyond this point) */
#define PICO_IP4_ANY (0x00000000U)
#define PICO_IP4_BCAST (0xffffffffU)

/* defined in modules/pico_ipv6.c */
#ifdef PICO_SUPPORT_IPV6
extern const uint8_t PICO_IPV6_ANY[PICO_SIZE_IP6];
#endif

static inline uint32_t pico_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

/* Debug */
//#define PICO_SUPPORT_DEBUG_MEMORY
//#define PICO_SUPPORT_DEBUG_TOOLS
#endif
