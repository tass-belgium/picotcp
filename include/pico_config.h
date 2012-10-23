#ifndef _INCLUDE_PICO_CONFIG
#define _INCLUDE_PICO_CONFIG



/*** USER CONFIGURATION ***/
#define PICO_SUPPORT_IPV4
//#define PICO_SUPPORT_IPV6

#define PICO_SUPPORT_ICMP4

#define PICO_SUPPORT_UDP
#define PICO_SUPPORT_TCP

//#define PICO_SUPPORT_DEBUG_MEMORY




/*************************/

/*** MACHINE CONFIGURATION ***/
/* Temporary (POSIX) stuff. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

static inline unsigned long PICO_TIME(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (t.tv_sec);
}

static inline unsigned long PICO_TIME_MS(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (t.tv_sec * 1000) + (t.tv_usec / 1000);
}


static inline uint32_t pico_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

static inline void PICO_IDLE(void)
{
  usleep(5000);
}

#define dbg printf



/** Endian-dependant constants **/

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

/* defined in modules/pico_ipv6.c */
#ifdef PICO_SUPPORT_IPV6
extern const uint8_t PICO_IPV6_ANY[PICO_SIZE_IP6];
#endif


#endif
