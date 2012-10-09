#ifndef _INCLUDE_PICO_CONFIG
#define _INCLUDE_PICO_CONFIG

/* Temporary (POSIX) stuff. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

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

#define dbg printf



/** Endian-dependant constants **/

#ifdef PICO_BIGENDIAN

# define PICO_IDETH_IPV4 0x0800
# define PICO_IDETH_ARP 0x0806
# define PICO_IDETH_IPV6 0x86DD

# define PICO_ARP_REQUEST 0x0001
# define PICO_ARP_REPLY   0x0002
# define PICO_ARP_HTYPE_ETH 0x0001

#else

# define PICO_IDETH_IPV4 0x0008
# define PICO_IDETH_ARP 0x0608
# define PICO_IDETH_IPV6 0xDD86

# define PICO_ARP_REQUEST 0x0100
# define PICO_ARP_REPLY   0x0200
# define PICO_ARP_HTYPE_ETH 0x0100

#endif

#endif
